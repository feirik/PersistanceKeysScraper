### Brief
Simple web scraper for scraping Windows registry keys used for persistance on the MITRE ATT&CK web site.


#### Usage: python3 persistance_reg_keys.py [-o]

### Command line options
#### -o --outfile `<output file path>` (optional)
Set path for the output file path. The keys are written line by line separated by newline character. The data needs to be processed as not all keys are valid. Output file is uploaded to repo.