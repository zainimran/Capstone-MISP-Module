import scrapy
import os
import tldextract
from pathlib import Path
import time

class InfoSecSpider(scrapy.Spider):
    name = "infosec_spider"
    start_urls = [
        'https://www.fireeye.com/blog/threat-research.html'
    ]

    def parse(self, response):
        domain = tldextract.extract(response.url).domain
        timestr = time.strftime("%Y%m%d-%H%M")
        output_dir = f'./output/{domain}/{timestr}'

        Path(output_dir).mkdir(parents=True, exist_ok=True)

        BLOG_POST_SELECTOR = 'div .c11v9 a ::attr("href")'
        for blog_post in response.css(BLOG_POST_SELECTOR).getall():
            yield response.follow(blog_post, self.parse_blog, cb_kwargs={'output_dir': output_dir})

    def parse_blog(self, response, output_dir):
        BLOG_TEXT_SELECTOR = 'div[itemprop*=articleBody].c00.c00v0 *::text'
        blog_text_list = response.css(BLOG_TEXT_SELECTOR).getall()

        filename = response.url.split("/")[-1].rstrip('.html')
        filepath = os.path.join(output_dir, filename)
        f = open(filepath, 'w')

        if blog_text_list is not None:
            blog_text = ''.join(blog_text_list)
            f.write(blog_text)
            self.log(f'Saved file {filename}')