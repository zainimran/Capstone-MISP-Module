import json
import os
import time
from pathlib import Path
from urllib.parse import urlparse

import scrapy
import tldextract


class InfoSecSpider(scrapy.Spider):
    name = "infosec_spider"

    def start_requests(self):
        start_urls = [
            'https://www.fireeye.com/blog/threat-research.html',
            'https://us-cert.cisa.gov/ncas/analysis-reports.xml', # already has support for stix-formatted reports, see https://us-cert.cisa.gov/sites/default/files/publications/MAR-10331466-1.v1.WHITE_stix.xml for example
        ]

        # https://docs.scrapy.org/en/latest/intro/tutorial.html#using-spider-arguments
        suppliedURL = getattr(self, 'url', None)
        if suppliedURL is not None:
            parsedURL = urlparse(suppliedURL)
            if parsedURL.netloc or parsedURL.path:
                url_to_append = f'{parsedURL.scheme}://{parsedURL.netloc}{parsedURL.path}'
                if not parsedURL.scheme:
                    url_to_append = f'https://{url_to_append}'
                start_urls.append(url_to_append)
        
        for url in start_urls:
            yield scrapy.Request(url, self.parse)
    
    def parse(self, response):
        domain = tldextract.extract(response.url).domain
        timestr = time.strftime("%Y%m%d-%H%M")
        output_dir = f'./output/{domain}/{timestr}'

        Path(output_dir).mkdir(parents=True, exist_ok=True)
        if domain == 'fireeye':
            BLOG_POST_SELECTOR = 'div .c11v9 a ::attr("href")'
            for blog_post in response.css(BLOG_POST_SELECTOR).getall():
                yield response.follow(blog_post, self.parse_blog, cb_kwargs={'output_dir': output_dir})
        elif domain == 'cisa':
            REPORT_SELECTOR = 'a ::attr("href")'
            for report in response.css(REPORT_SELECTOR).getall():
                yield response.follow(report, self.parse_report, cb_kwargs={'output_dir': output_dir})
        else:
            text_list = ''.join(response.xpath('//text()[re:test(., "\w+")]').getall()).strip()
            self.write_output(response.url, text_list, output_dir, custom=True)

    def parse_blog(self, response, output_dir):
        BLOG_TEXT_SELECTOR = 'div[itemprop*=articleBody].c00.c00v0 *::text'
        blog_text_list = response.css(BLOG_TEXT_SELECTOR).getall()

        self.write_output(response.url, blog_text_list, output_dir)
    
    def parse_report(self, response, output_dir):
        # REPORT_TEXT_SELECTOR = 'div.region.region-content'
        # report_text_list = response.css(REPORT_TEXT_SELECTOR).xpath('./descendant::text()[not(ancestor::style)]').getall()
        REPORT_TEXT_SELECTOR = 'table#cma-table *::text'
        report_text_list = response.css(REPORT_TEXT_SELECTOR).getall()

        self.write_output(response.url, report_text_list, output_dir)

    def write_output(self, url, text_list, output_dir, custom=False):
        filename = '{}.json'.format(url.split("/")[-1].rstrip('.html'))
        if custom:
            filename = 'output.json'
        filepath = os.path.join(output_dir, filename)
        f = open(filepath, 'w')

        if text_list is not None:
            text = ''.join(text_list)
            output = { 'url': url, 'scraped output': text }
            json.dump(output, f, indent=4)
            self.log(f'Saved file {filename}')