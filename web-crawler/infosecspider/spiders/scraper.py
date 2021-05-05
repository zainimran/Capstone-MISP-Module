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
            'https://securelist.com/',
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

        f_name_index = -1
        if domain == 'fireeye':
            POST_SELECTOR = 'div .c11v9 a ::attr("href")'
            TEXT_SELECTOR = 'div[itemprop*=articleBody].c00.c00v0 *::text'
        elif domain == 'securelist':
            POST_SELECTOR = 'a.c-card__link ::attr("href")'
            TEXT_SELECTOR = 'div.js-reading-wrapper *::text'
            f_name_index = -3
        elif domain == 'cisa':
            POST_SELECTOR = 'a ::attr("href")'
            TEXT_SELECTOR = 'table#cma-table *::text'
        else:
            text_list = ''.join(response.xpath('//text()[re:test(., "\w+")]').getall()).strip()
            self.write_output(response.url, text_list, output_dir, custom=True)
            return

        for post in response.css(POST_SELECTOR).getall():
            yield response.follow(post, self.parse_post, cb_kwargs={'output_dir': output_dir, 'text_selector': TEXT_SELECTOR, 'f_name_index': f_name_index})

    def parse_post(self, response, output_dir, text_selector, f_name_index):
        text_list = response.css(text_selector).getall()
        self.write_output(response.url, text_list, output_dir, f_name_index)

    def write_output(self, url, text_list, output_dir, f_name_index=-1, custom=False):
        filename = '{}.json'.format(url.split("/")[f_name_index].rstrip('.html'))
        if custom:
            filename = 'output.json'
        filepath = os.path.join(output_dir, filename)
        f = open(filepath, 'w')

        if text_list is not None:
            text = ''.join(text_list)
            output = { 'url': url, 'scraped output': text }
            json.dump(output, f, indent=4)
            self.log(f'Saved file {filename}')