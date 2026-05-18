#!/usr/bin/env python3
import argparse
import asyncio
import hashlib
import logging
import random
import re
import time
from collections import defaultdict, deque, Counter
from pathlib import Path
from typing import List, Dict
from urllib.parse import urlparse
import aiohttp

# ====================== 配置 ======================
CRITICAL_FINGERPRINTS = {"wso", "filesman", "b374k", "c99", "r57", "sym", "indoxploit", "madspot", "priv8"}

CRITICAL_REGEX = [
    r"system\s*\(", r"exec\s*\(", r"passthru\s*\(", r"shell_exec\s*\(",
    r"eval\s*\(", r"assert\s*\(", r"base64_decode\s*\(", r"gzinflate\s*\(",
]

ALLOWED_CONTENT_TYPES = {'text/html', 'text/plain', 'application/xhtml+xml'}

MAX_RESPONSE_SIZE = 2_000_000
MAX_HASHES_PER_HOST = 120

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
]

class WebshellDetector:
    def __init__(self, args):
        self.args = args
        self.setup_logging()
        self.session = None
        
        self.global_semaphore = asyncio.Semaphore(args.global_limit)
        self.host_semaphores = defaultdict(lambda: asyncio.Semaphore(4))
        
        self.error_page_hashes = defaultdict(lambda: deque(maxlen=MAX_HASHES_PER_HOST))
        self.compiled_regex = [re.compile(p, re.IGNORECASE) for p in CRITICAL_REGEX]
        self.title_re = re.compile(r'<title>(.*?)</title>', re.I | re.S)
        
        self.seen_urls = set()
        self.result_file = None
        self.verbose_file = None

        # Adaptive
        self.stats = Counter()
        self.last_adjust_time = time.time()
        self.current_global_limit = args.global_limit

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s | %(levelname)s | %(message)s',
            handlers=[logging.FileHandler('webshell_detector.log', encoding='utf-8')]
        )
        self.logger = logging.getLogger(__name__)

    async def init_session(self):
        connector = aiohttp.TCPConnector(limit=600, ttl_dns_cache=300, keepalive_timeout=35, ssl=False)
        timeout = aiohttp.ClientTimeout(total=22, connect=12, sock_read=18)

        self.session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        self.result_file = open(self.args.output, 'w', encoding='utf-8')
        self.verbose_file = open('findings_verbose.log', 'w', encoding='utf-8')

    def get_random_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": random.choice(["text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                   "text/html,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"]),
            "Accept-Language": random.choice(["en-US,en;q=0.9", "zh-CN,zh;q=0.9,en;q=0.8"]),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Cache-Control": random.choice(["max-age=0", "no-cache"]),
            "Sec-Fetch-Mode": "navigate",
        }

    def safe_url(self, base: str, filename: str) -> str:
        return f"{base.rstrip('/')}/{filename.lstrip('/')}"

    async def head_precheck(self, url: str):
        """升级版 HEAD：更宽松 + fallback"""
        try:
            async with self.session.head(url, headers=self.get_random_headers(),
                                       allow_redirects=True, timeout=10) as resp:
                if resp.status in {200, 301, 302, 403}:
                    ct = resp.headers.get('Content-Type', '').lower()
                    if any(allowed in ct for allowed in ALLOWED_CONTENT_TYPES) or resp.status in {301, 302, 403}:
                        return True
                return False
        except:
            return False  # HEAD 失败直接走 GET

    async def check_url(self, base_url: str, filename: str):
        full_url = self.safe_url(base_url, filename)
        if full_url in self.seen_urls:
            return
        self.seen_urls.add(full_url)

        host = urlparse(full_url).netloc

        async with self.global_semaphore, self.host_semaphores[host]:
            # HEAD Precheck
            if not await self.head_precheck(full_url):
                # HEAD 失败或不明确 → 直接 GET
                pass

            for attempt in range(3):
                try:
                    async with self.session.get(full_url, headers=self.get_random_headers(),
                                              allow_redirects=self.args.allow_redirect) as resp:
                        self.stats[resp.status] += 1

                        ct = resp.headers.get('Content-Type', '').lower()
                        if not any(allowed in ct for allowed in ALLOWED_CONTENT_TYPES):
                            return

                        body = await resp.content.read(MAX_RESPONSE_SIZE + 8192)
                        if len(body) > MAX_RESPONSE_SIZE:
                            return
                        content = body.decode('utf-8', errors='ignore')

                        if self.is_waf_or_blocked(resp.status, content):
                            self._adaptive_adjust()
                            return
                        if self.is_likely_error_page(host, content):
                            return

                        title_match = self.title_re.search(content)
                        title = title_match.group(1).strip() if title_match else ""

                        score, risk, matched = self.calculate_risk(content, title)

                        if score >= self.args.min_score and len(matched) >= 2:
                            self.result_file.write(full_url + "\n")
                            self.result_file.flush()

                            verbose = (f"URL: {full_url}\nScore: {score} | Risk: {risk}\n"
                                      f"Title: {title}\nMatched: {matched}\n{'-'*80}\n")
                            self.verbose_file.write(verbose)
                            self.verbose_file.flush()

                            color = "\033[1;32m" if score >= 75 else "\033[1;33m"
                            print(f"{color}🚨 [{risk}] {score} → {full_url}\033[0m")

                    self._adaptive_adjust()
                    break

                except (aiohttp.ClientError, asyncio.TimeoutError):
                    self.stats['timeout'] += 1
                    self._adaptive_adjust()
                    if attempt < 2:
                        await asyncio.sleep(random.uniform(0.8, 2.5))
                    continue
                except Exception:
                    break

    def _adaptive_adjust(self):
        """完整自适应并发控制"""
        now = time.time()
        if now - self.last_adjust_time < 8:
            return

        total = sum(self.stats.values())
        if total < 200:
            return

        rate_429 = self.stats[429] / total
        rate_403 = self.stats[403] / total
        rate_200 = self.stats[200] / total

        old = self.current_global_limit

        if rate_429 > 0.07 or rate_403 > 0.12:
            self.current_global_limit = max(40, self.current_global_limit - 30)
            self.global_semaphore = asyncio.Semaphore(self.current_global_limit)
            self.logger.warning(f"↓ Adaptive DOWN → {self.current_global_limit} (429:{rate_429:.1%}, 403:{rate_403:.1%})")
        elif rate_200 > 0.78 and self.current_global_limit < self.args.global_limit * 0.95:
            self.current_global_limit = min(self.args.global_limit, self.current_global_limit + 25)
            self.global_semaphore = asyncio.Semaphore(self.current_global_limit)
            self.logger.info(f"↑ Adaptive UP → {self.current_global_limit}")

        self.last_adjust_time = now
        self.stats.clear()

    def is_waf_or_blocked(self, status: int, content: str) -> bool:
        if status not in {200, 301, 302}:
            return True
        text = content.lower()[:1500]
        signs = ["cloudflare", "cf-ray", "captcha", "sucuri", "attention required", "access denied"]
        return any(sign in text for sign in signs)

    def is_likely_error_page(self, host: str, content: str) -> bool:
        if len(content) < 400:
            return True
        short_hash = hashlib.md5(content[:2800].encode()).hexdigest()
        self.error_page_hashes[host].append(short_hash)
        return self.error_page_hashes[host].count(short_hash) >= 4

    def calculate_risk(self, content: str, title: str):
        # （保持 v6.6 的加强版 scoring 逻辑）
        text_lower = content.lower()
        title_lower = title.lower() if title else ""
        score = 0
        matched = []

        for fp in CRITICAL_FINGERPRINTS:
            if fp in text_lower or fp in title_lower:
                return 100, "CRITICAL", [f"FINGERPRINT:{fp}"]

        php_context = bool(re.search(r'<\?php|<\?', content[:800]))
        critical_count = sum(1 for pattern in self.compiled_regex if pattern.search(content))

        score += critical_count * 30
        if critical_count >= 1:
            matched.append(f"REGEX×{critical_count}")

        if critical_count >= 2: score += 25
        if critical_count >= 3: score += 20
        if php_context and critical_count >= 2:
            score = int(score * 1.65)
            matched.append("PHP_MULTI×1.65")

        if "<textarea" in text_lower and any(k in text_lower for k in ["cmd", "exec", "shell", "system"]):
            score += 22
            matched.append("TEXTAREA_CMD")
        if any(x in text_lower for x in ['type="file"', 'upload file', 'file manager', 'uploader']):
            score += 22
            matched.append("UPLOAD_UI")

        if php_context:
            score += 12

        final_score = min(int(score), 100)
        risk = "CRITICAL" if final_score >= 80 else "HIGH" if final_score >= 60 else "MEDIUM" if final_score >= self.args.min_score else "LOW"
        return final_score, risk, matched

    async def producer(self, queue: asyncio.Queue, directories: List[str], filenames: List[str]):
        """真·全局随机化（推荐用于 < 500万目标）"""
        targets = [(d, f) for d in directories for f in filenames]
        random.shuffle(targets)
        for target in targets:
            await queue.put(target)

    async def worker(self, queue: asyncio.Queue):
        while True:
            item = None
            try:
                item = await queue.get()
                await self.check_url(*item)
            except asyncio.CancelledError:
                break
            except Exception:
                pass
            finally:
                if item is not None:
                    queue.task_done()

    async def run(self):
        await self.init_session()
        try:
            directories = self.load_file(self.args.directories)
            filenames = self.load_file(self.args.dictionary)

            total = len(directories) * len(filenames)
            self.logger.info(f"Scan started → {total:,} targets | Global: {self.args.global_limit} | Adaptive + Stealth")

            queue: asyncio.Queue = asyncio.Queue(maxsize=15000)
            workers = [asyncio.create_task(self.worker(queue)) for _ in range(self.args.concurrency)]
            producer = asyncio.create_task(self.producer(queue, directories, filenames))

            await producer
            await queue.join()

            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

            self.logger.info("Scan completed successfully.")
        finally:
            if self.result_file: self.result_file.close()
            if self.verbose_file: self.verbose_file.close()
            if self.session: await self.session.close()

    def load_file(self, filepath: str) -> List[str]:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]


def main():
    parser = argparse.ArgumentParser(description="Webshell Detector v6.7 - Final Stealth + Adaptive")
    parser.add_argument('--directories', '-d', required=True)
    parser.add_argument('--dictionary', '-w', required=True)
    parser.add_argument('--output', '-o', default='found_webshells.txt')
    parser.add_argument('--min-score', type=int, default=55)
    parser.add_argument('--concurrency', '-c', type=int, default=150)
    parser.add_argument('--global-limit', type=int, default=220)
    parser.add_argument('--allow-redirect', action='store_true')
    args = parser.parse_args()

    detector = WebshellDetector(args)
    asyncio.run(detector.run())


if __name__ == "__main__":
    main()
