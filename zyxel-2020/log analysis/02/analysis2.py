with open('exam2.txt', 'r') as f:
    line = f.readlines();

ips = []

for i in range(len(line)):
    print(i)
    ips.append(line[i].split()[1].split(':')[0])

iplist = []
aplist = []

for ip in ips:
    if iplist.count(ip) != 0:
        continue
    
    print('processing...')
    iplist.append(ip)
    aplist.append(ips.count(ip))
    
print('sorted...')
biggest = [aplist.index(x) for x in sorted(aplist, reverse=True)[:3]]

for i in biggest:
    print('{}: {}'.format(iplist[i], aplist[i]))
    
# 94.102.49.91: 26444
# 176.122.7.93: 16786
# 79.124.62.34: 11017
#
# flag{ffd04754ddf2b714d0779f4d415530550b4e4b91}