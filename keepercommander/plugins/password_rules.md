To specify the rules for password complexity to use add a custom field
The password rules consists of 4 or 5 integers separated by comma.
In case of 5 integers the first component is password length. 
Positive numbers mean "at least" while negative or zero "exactly"

### Five digits password rules

```
Name: cmdr:rules
Value: 25,4,6,-3,0
```

This would generate a new password with :
```
 25 password    characters (at least)
  4 uppercase   characters (at least)
  6 lowercase   characters (at least)
  3 numerical   characters (exactly)
  0 punctuation characters (exactly)
```

### Four digits password rules

```
Name: cmdr:rules
Value: 4,6,3,2
```

This would generate a new password with :
```
 20 password    characters (the default minimum password length)
  4 uppercase   characters (at least)
  6 lowercase   characters (at least)
  3 numerical   characters (at least)
  2 punctuation characters (at least)
```
