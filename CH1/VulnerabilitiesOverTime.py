import glob
import json
import csv


##
## Step 1: Collect the data
##

vulnsPerYear = {} # array we will graph in a bar chart
lowVulnsPerYear = {} # array we will graph in a bar chart
mediumVulnsPerYear = {} # array we will graph in a bar chart
highVulnsPerYear = {} # array we will graph in a bar chart

#iterate through all json files in the current directory
for filename in glob.glob('*.json'):
    
    print("Processing file %s" % (filename))
    

    year = filename.split('.')[1].split('-')[-1] # we are assuming the filename format is "nvdcve-1.0-YYYY.json"
    with open(filename) as json_file:  
        data = json.load(json_file)

        # we are assuming the file follows this format: https://csrc.nist.gov/schema/nvd/feed/1.0/nvd_cve_feed_json_1.0.schema
        
        for cve in data["CVE_Items"]:
        
            if 'baseMetricV2' in cve['impact']:
                year = cve['publishedDate'].split('-')[0]
                if year not in vulnsPerYear:
                    vulnsPerYear[year] = 0
                    highVulnsPerYear[year] = 0
                    mediumVulnsPerYear[year] = 0
                    lowVulnsPerYear[year] = 0
                    
                if cve['impact']['baseMetricV2']['severity'] == 'HIGH':
                    highVulnsPerYear[year] +=1
                elif cve['impact']['baseMetricV2']['severity'] == 'MEDIUM':
                    mediumVulnsPerYear[year] +=1
                elif cve['impact']['baseMetricV2']['severity'] == 'LOW':
                    lowVulnsPerYear[year] +=1
                else:
                    print("Unknown severity: %s" % (cve['impact']['baseMetricV2']['severity']))
                
                vulnsPerYear[year] +=1
           
                
        



##
## Step 2: Use the data to create a CSV file
##


with open('vulnsOverTime.csv', 'wb') as csvfile:
    filewriter = csv.writer(csvfile, delimiter=',',
                            quotechar='|', quoting=csv.QUOTE_MINIMAL)

    filewriter.writerow(['Year', 'Total','High','Medium','Low'])
    for y in (sorted(vulnsPerYear)):
        filewriter.writerow([y, vulnsPerYear[y],highVulnsPerYear[y],mediumVulnsPerYear[y],lowVulnsPerYear[y]])
        print("Number of CVEs for year %s : %s (L: %s, M: %s, H: %s)" % (y, vulnsPerYear[y], lowVulnsPerYear[y], mediumVulnsPerYear[y], highVulnsPerYear[y])) 
    
