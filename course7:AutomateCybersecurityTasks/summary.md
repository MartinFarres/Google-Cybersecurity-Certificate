# Automate Cybersecurity Tasks With Python

[**Module 1: Introduction to Python**](#)

[**Module 2: Write effective Python code**](#)

[**Module 3: Work with strings and lists**](#)

[**Module 4: Python in practice**](#)

**Course too basic - Omitted most of the summary**

### **What is a Regular Expression (Regex)?**

A **regular expression** is a sequence of characters that defines a search pattern. It is commonly used to search, extract, and manipulate text like:

- IP addresses
- Email addresses
- Device IDs
- Usernames and logins

---

### **Using Regex in Python**

To use regular expressions in Python, import the `re` module:

```python
import re
```

You’ll commonly use:

```python
re.findall(pattern, string)
```

- Returns all matches of `pattern` in the given `string` as a list.

---

### **Character Type Symbols**

| Symbol | Matches                                                         |
| ------ | --------------------------------------------------------------- |
| `\w`   | Alphanumeric characters + underscore (`a-z`, `A-Z`, `0-9`, `_`) |
| `\d`   | Single digit (`0-9`)                                            |
| `\s`   | Whitespace (spaces, tabs)                                       |
| `.`    | Any character (except newline)                                  |
| `\.`   | A literal period `.`                                            |

---

### **Quantifiers**

These symbols specify how many times a character or pattern should appear:

| Symbol  | Meaning                   |
| ------- | ------------------------- |
| `+`     | One or more               |
| `*`     | Zero or more              |
| `{n}`   | Exactly `n` times         |
| `{n,m}` | Between `n` and `m` times |

---

### **Constructing Patterns**

Break the search into parts and use regex symbols to match:
**Example Goal**: Extract usernames and login counts from:

```python
employee_logins_string = "1001 bmoreno: 12 Marketing 1002 tshah: 7 Human Resources 1003 sgilmore: 5 Finance"
```

**Regex breakdown**:

- `\w+` → username
- `:` → literal colon
- `\s` → space
- `\d+` → login count

**Combined pattern**:

```python
re.findall(r"\w+:\s\d+", employee_logins_string)
# Output: ['bmoreno: 12', 'tshah: 7', 'sgilmore: 5']
```
