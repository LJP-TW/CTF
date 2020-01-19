#!/usr/bin/python3.8
d = 62327557137569567679643031374421029290466524060604475125850668262265971735555869509428697187592660961324627497861635853578587090977640206991864938856422414215600015897040875459759130532935957720449772007919524682085843579636707201198079284326134237206210134048054767142287354989931753253806799485124112137333
c = 39212571777327575925533069277559648999675123587881336293163421040602489819189501122740238850560345127781953899734776145828303937409205976122166154238106388104185231412802739769882961426581742119781215821969366448585378600143585866771501710468362019388674964898458816915193204452991237346491822887339522282272
e = 65537
n = 66575847316842910227703778782257859939846868019881598668778017209748594077632222639384378250888439759144847401635694384092247774124384422551150721177301878771187376993014056302918196758476211287642180466360524238394109998731292629445767062782267736527149361318808688336363697187382888809106245677337925583341
m = 365007415180410418873801215123619082

myM = pow(c, d, n)
print('myM : {}'.format(myM))
print('bin(myM): {}'.format(bin(myM)))
print('myM % 16: {}'.format(myM % 16))

_c = c

mrange = [0, n]

i = 0
while True:
    i += 1
    _c = pow(2, e, n) * _c
    myM = pow(_c, d, n)
    # print('myM : {}'.format(myM))
    # print('bin(myM): {}'.format(bin(myM)))
    # print('myM % 16: {}'.format(myM % 16))

    if (myM % 16) % 2 == 1:
        mrange[0] = (mrange[1] + mrange[0]) // 2
    else:
        mrange[1] = (mrange[1] + mrange[0]) // 2

    if mrange[1] - mrange[0] < 128 or mrange[0] > mrange[1]:
        break

print('i = {}'.format(i))
print('mrange = {}'.format(mrange))



