# crawler/breadth_spider.py
import scrapy
from scrapy.crawler import CrawlerProcess
import os

class BreadthSpider(scrapy.Spider):
    name = "breadth"
    custom_settings = {"LOG_LEVEL": "ERROR", "ROBOTSTXT_OBEY": False}
    def __init__(self, start_urls=None, max_pages=100, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.start_urls = start_urls or []
        self.count = 0
        self.max_pages = int(max_pages)

    def parse(self, response):
        self.count += 1
        yield {"url": response.url, "status": response.status}
        if self.count >= self.max_pages:
            return
        for href in response.css('a::attr(href)').getall():
            yield response.follow(href, self.parse)

def run_breadth(start_list, max_pages=200, out_file="breadth_urls.txt"):
    process = CrawlerProcess()
    spider = BreadthSpider(start_urls=start_list, max_pages=max_pages)
    process.crawl(spider)
    process.start()
    # results go to stdout; you can extend pipeline to save file
