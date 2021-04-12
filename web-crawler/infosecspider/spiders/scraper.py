import scrapy
import os
import tldextract
from pathlib import Path
import time

class InfoSecSpider(scrapy.Spider):
    name = "infosec_spider"
    start_urls = [
        'https://www.fireeye.com/blog/threat-research.html',
        'https://us-cert.cisa.gov/ncas/analysis-reports.xml', # already has support for stix-formatted reports, see https://us-cert.cisa.gov/sites/default/files/publications/MAR-10331466-1.v1.WHITE_stix.xml for example
    ]

    def parse(self, response):
        domain = tldextract.extract(response.url).domain
        timestr = time.strftime("%Y%m%d-%H%M")
        output_dir = f'./output/{domain}/{timestr}'

        Path(output_dir).mkdir(parents=True, exist_ok=True)
        if (domain == 'fireeye'):
            BLOG_POST_SELECTOR = 'div .c11v9 a ::attr("href")'
            for blog_post in response.css(BLOG_POST_SELECTOR).getall():
                yield response.follow(blog_post, self.parse_blog, cb_kwargs={'output_dir': output_dir})

        if (domain == 'cisa'):
            REPORT_SELECTOR = 'a ::attr("href")'
            for report in response.css(REPORT_SELECTOR).getall():
                yield response.follow(report, self.parse_report, cb_kwargs={'output_dir': output_dir})

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
    
    def parse_report(self, response, output_dir):
        # REPORT_TEXT_SELECTOR = 'div.region.region-content'
        # report_text_list = response.css(REPORT_TEXT_SELECTOR).xpath('./descendant::text()[not(ancestor::style)]').getall()
        REPORT_TEXT_SELECTOR = 'table#cma-table *::text'
        report_text_list = response.css(REPORT_TEXT_SELECTOR).getall()

        filename = response.url.split("/")[-1]
        filepath = os.path.join(output_dir, filename)
        f = open(filepath, 'w')

        if report_text_list is not None:
            report_text = ''.join(report_text_list)
            f.write(report_text)
            self.log(f'Saved file {filename}')