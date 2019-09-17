import textdistance

targets = [
    'dqzkenxmpsdoe_qkihmd',
    'jffglzbo_zghqpnqqfjs',
    'kdwx_vl_rnesamuxugap',
    'ozntzohegxagreedxukr',
    'xujaowgbjjhydjmmtapo',
    'pwbzgymqvpmznoanomzx',
    'qaqhrjofhfiuyt_okwxn',
    'a_anqkczwbydtdwwbjwi',
    'zoljafyuxinnvkxsskdu',
    'irdlddjjokwtpbrrr_yj',
    'cecckcvaltzejskg_qrc',
    'vlpwstrhtcpxxnbbcbhv',
    'spirysagnyujbqfhldsk',
    'bcyqbikpuhlwordznpth',
    '_xkiiusddvvicipuzyna',
    'wsxyupdsqatrkzgawzbt',
    'ybg_wmftbdcvlhhidril',
    'ryvmngilaqkbsyojgify',
    'mvefjqtxzmxf_vcyhelf',
    'hjhofxwrk_rpwli_mxv_',
    'enupmannieqqzcyevs_w',
    'uhmvvb_cfgjkggjpavub',
    'gktdphqiswomuwzvjtog',
    'lgoehepwclbaifvtfoeq',
    'nm_uxrukmof_fxsfpcqz',
    'ttsbclzyyuslmutcylcm']

myBasicInput = 'dqzkenxmpsdoe_kqdihm'
cands = 'abcdefghijklmnopqrstuvwxyz_'

for cand in cands:
    totalDistance = 0
    for target in targets:
        myInput = myBasicInput + cand
        distance = textdistance.levenshtein.distance(myInput, target)
        totalDistance += distance
        print('%s vs %s : %d' % (myInput, target, distance))

    # print('total distance : %d' % (totalDistance))
    # print('required distance : %d' % (0x1f9))
    print('total - required : %d' % (totalDistance - 0x1f9))
    if (totalDistance - 0x1f9) == 0:
        print('answer : %s' % (myInput))
        exit()
