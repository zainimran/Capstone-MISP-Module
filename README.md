# Capstone-MISP-Module

- [Capstone-MISP-Module](#capstone-misp-module)
  - [How to run the spider module](#how-to-run-the-spider-module)
## 1) How to run the spider module
1. Navigate to `Capstone-MISP-Module/web-crawler`
2. If not done already, install project dependencies with `pipenv install`
3. Open the python virtual environment for spider module with `pipenv shell`
4. Navigate to `infosecspider/spiders`
5. Run the spider with `scrapy runspider scraper.py`, where `scraper.py` is the name of the scraping script in `infosecspider/spiders`


## 2) How to run the ioc-extraction module
1. Navigate to `Capstone-MISP-Module/`
2. `unzip cyobstract.zip` #Cyobstract IOC extraction tool authored by Sam-Perl, et al.
3. `python cyobstract/setup.py install` #install cyobstract dependencies
4. `pip install --upgrade --force-reinstall progress` #fixes library errors
5. `python /util/ioc_extract.py` #returns a dictionary of extracted IoCs or None
