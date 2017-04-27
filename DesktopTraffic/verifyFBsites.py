import shutil
import sqlite3
#python shutil to take urls and copy screenshots to new folder to look at IF they found connect page but not FB verified
#can also use sqlite3 for python and copy a query and get results to use 

conn = sqlite3.connect('100sites/100.sqlite')

c = conn.cursor()

for row in c.execute('SELECT sv.site_url, fb.connect_page_found, fb.connect_successful, fb.fb_api_verified FROM site_visits as sv LEFT JOIN fb_login as fb ON sv.visit_id = fb.visit_id WHERE fb.connect_page_found = 1;'):
	print row[0][7:]
	shutil.move("/Users/max1995/Desktop/Thesis/DesktopTraffic/100sites/screenshots/"+ row[0][7:] + ".png", "/Users/max1995/Desktop/Thesis/DesktopTraffic/verifyScreenshots/" + row[0][7:] + ".png")

