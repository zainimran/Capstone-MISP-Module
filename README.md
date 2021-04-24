# Capstone-MISP-Module

- [Capstone-MISP-Module](#capstone-misp-module)
  - [How to run the spider module](#how-to-run-the-spider-module)
## How to run the spider module
1. Navigate to `Capstone-MISP-Module/web-crawler`
2. If not done already, install project dependencies with `pipenv install`
3. Open the python virtual environment for spider module with `pipenv shell`
4. Navigate to `infosecspider/spiders`
5. Run the spider with `scrapy runspider scraper.py`, where `scraper.py` is the name of the scraping script in `infosecspider/spiders`