sort -R ~/projecto/research_projects/mcscraper/in/master_ip_list.txt | head -n 30 > testin.txt
python frey_bulk_info.py testin.txt . > testoutinfo.json
