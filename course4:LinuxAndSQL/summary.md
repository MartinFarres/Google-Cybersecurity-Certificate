# Tools of the trade: Linux and SQL

**Module 1: Introduction to operating systems**

**Module 2: The Linux operating system**

**Module 3: Linux commands in the Bash shell**

**Module 4: Databases and SQL**

**( Skipped most of the summary because topics are to basic )**

---

## Module 1: Intro to OS

Below are several resources that include information on operating systems and their vulnerabilities:

- [Microsoft Security Response Center (MSRC)](https://msrc.microsoft.com/update-guide/vulnerability): A list of known vulnerabilities affecting Microsoft products and services.
- [Apple Security Updates](https://support.apple.com/en-us/HT201222): A list of security updates and information for Apple® operating systems, including macOS and iOS, and other products.
- [Common Vulnerabilities and Exposures (CVE) Report for Ubuntu](https://ubuntu.com/security/cves): A list of known vulnerabilities affecting Ubuntu, which is a specific distribution of Linux.
- [Google Cloud Security Bulletin](https://cloud.google.com/support/bulletins): A list of known vulnerabilities affecting Google Cloud products and services.

### The OS at work

#### Booting the Computer

When you boot, or turn on, your computer, either a BIOS or UEFI microchip is activated. The Basic Input/Output System (BIOS) is a microchip that contains loading instructions for the computer and is prevalent in older systems. The Unified Extensible Firmware Interface (UEFI) is a microchip that contains loading instructions for the computer and replaces BIOS on more modern systems.

The BIOS and UEFI chips both perform the same function for booting the computer. BIOS was the standard chip until 2007, when UEFI chips increased in use. Now, most new computers include a UEFI chip. UEFI provides enhanced security features.

The BIOS or UEFI microchips contain a variety of loading instructions for the computer to follow. For example, one of the loading instructions is to verify the health of the computer’s hardware.

The last instruction from the BIOS or UEFI activates the bootloader. The bootloader is a software program that boots the operating system. Once the operating system has finished booting, your computer is ready for use..
BIOS is not scanned by the antivirus software, so it can be vulnerable to malware infection.

#### Virtualization Technology

Virtualization is the process of using software to create virtual representations of various physical machines. Virtual systems don’t use dedicated physical hardware. Instead, they use software-defined versions of the physical hardware

Here's a structured and concise version of your text using `####` for the titles, as requested:

---

#### Benefits of Virtual Machines

Security professionals commonly use virtualization and virtual machines because they can enhance both **security** and **efficiency** in their work.

---

#### Security

One key benefit of virtualization is that it provides an **isolated environment**, or **sandbox**, on the physical host machine. Each virtual machine (VM) is a “guest” that is **separated from the host** and other guest machines. This isolation adds a layer of security.

- If one VM is infected with malware, it can be contained and handled securely.
- Security professionals can safely analyze malicious software by running it in a VM, reducing the risk to the host system.

> **Note:** While virtual machines improve security, they are not completely immune. Advanced malware may escape the virtual environment and affect the host machine, so VMs should not be fully trusted in high-risk situations.

---

#### Efficiency

Virtual machines also improve efficiency:

- Multiple VMs can run on a single physical machine.
- Users can easily switch between VMs to perform different security tasks like testing or analyzing applications.

A helpful comparison is that **VMs are like a city bus**:

- A bus carries many people efficiently, using fewer resources than each person driving separately.
- Likewise, VMs reduce the need for multiple physical machines by hosting them all on one device.

---

#### Managing Virtual Machines

Virtual machines are managed by software called a **hypervisor**. Hypervisors connect virtual machines to physical hardware and allocate shared resources between them.

One notable hypervisor is **KVM (Kernel-based Virtual Machine)**:

- Open-source and integrated into the Linux kernel.
- Compatible with most major Linux distributions.
- Allows users to create and run VMs on Linux without installing extra software.

---

Let me know if you'd like this formatted for a presentation or document!

### GUI vs CLI

## Module 2: The Linux operating system

### Linux Distributions

#### Parent Distributions

- Red Hat Enterprise Linux (CentOS)
- Slackware (SUSE)
- Debian (Ubuntu and KALI LINUX)

#### Package Managers

A package is a piece of software that can be combined with other packages to form an application. Some packages may be large enough to form applications on their own.

Packages contain the files necessary for an application to be installed. These files include dependencies, which are supplemental files used to run an application.

Package managers can help resolve any issues with dependencies and perform other management tasks. A package manager is a tool that helps users install, manage, and remove packages or applications. Linux uses multiple package manage

- Red Hat Package Manager used for Red Hat (.rpm) -> Yellowdog Updater Modified (YUM)
- dpkg used for Debian (.deb) -> Advanced Package Tool (APT)

### The Shell

Types of shell:

- Bourne-Again Shell (bash)
- C shell (csh)
- Kon SHell (ksh)
- Enhanced C shell (tcsh)
- Z shell (zsh)

## Module 3: Linux commands in the Bash shell

### Navifate the linux file system

![alt text](/course4/resources/linux-file-system.png)

#### Standard FHS directories

Directly below the root directory, you’ll find standard FHS directories. In the diagram, home, bin, and etc are standard FHS directories. Here are a few examples of what standard directories contain:

- /home: Each user in the system gets their own home directory.

- /bin: This directory stands for “binary” and contains binary files and other executables. Executables are files that contain a series of commands a computer needs to follow to run programs and perform other functions.

- /etc: This directory stores the system’s configuration files.

- /tmp: This directory stores many temporary files. The /tmp directory is commonly used by attackers because anyone in the system can modify data in these files.

- /mnt: This directory stands for “mount” and stores media, such as USB drives and hard drives.

### Mange file content in bash

**grep**

**pipe ( | )**

**find** -> find /home/analyst/projects -name "_log_"
the output would be all files in the projects directory that contain log surrounded by zero or more characters.
Analysts might also use find to find files or directories last modified within a certain time frame. The -mtime option can be used for this search. For example, entering find /home/analyst/projects -mtime -3 returns all files and directories in the projects directory that have been modified within the past three days.

### Authenticate and authorize Users

#### Reading permissions

In Linux, file and directory permissions are represented with a 10-character string. These permissions include:

- **read (r)**:

  - **Files**: Allows reading contents.
  - **Directories**: Allows listing contents.

- **write (w)**:

  - **Files**: Allows editing.
  - **Directories**: Allows creating new files.

- **execute (x)**:

  - **Files**: Allows running if executable.
  - **Directories**: Allows access/navigation.

Permissions apply to three owner types:

- **user**: the file owner
- **group**: the owner's group
- **other**: all other users

Each character in the string has a meaning:

| Character | Example    | Meaning                         |
| --------- | ---------- | ------------------------------- |
| 1st       | `d` or `-` | `d` for directory, `-` for file |
| 2nd       | `r` or `-` | Read for user                   |
| 3rd       | `w` or `-` | Write for user                  |
| 4th       | `x` or `-` | Execute for user                |
| 5th       | `r` or `-` | Read for group                  |
| 6th       | `w` or `-` | Write for group                 |
| 7th       | `x` or `-` | Execute for group               |
| 8th       | `r` or `-` | Read for other                  |
| 9th       | `w` or `-` | Write for other                 |
| 10th      | `x` or `-` | Execute for other               |

---

#### Exploring existing permissions

Use the `ls` command with options to inspect permissions:

- `ls -a`: Shows hidden files (starting with `.`)
- `ls -l`: Lists files with permissions, owner, size, timestamp
- `ls -la`: Combines both to show all files with details

---

### Changing permissions

Follow the **principle of least privilege**: only give users the minimum necessary access.

Use the `chmod` command to change permissions:

```bash
chmod u+rwx,g+rwx,o+rwx login_sessions.txt
```

Removes all permissions:

```bash
chmod u-rwx,g-rwx,o-rwx login_sessions.txt
```

Sets permissions exactly (overwrites existing ones):

```bash
chmod u=r,g=r,o=r login_sessions.txt
```

**Characters used in chmod**:

| Character | Meaning                               |
| --------- | ------------------------------------- |
| `u`       | user permissions                      |
| `g`       | group permissions                     |
| `o`       | other permissions                     |
| `+`       | add permissions                       |
| `-`       | remove permissions                    |
| `=`       | assign exact permissions (overwrites) |

**Note**: Use commas without spaces to separate multiple changes:

```bash
chmod u=rw,g=r,o= bonuses.txt
```

---

#### Example: Principle of least privilege in action

A file `bonuses.txt` has permissions `-rw-rw----`. This gives read/write access to both user and group. But only `hrrep1` should access it.

To restrict access:

```bash
chmod g-rw bonuses.txt
```

Now, only `hrrep1` (the user) can access the file.

#### User and Group Management in Linux

This guide summarizes key commands for managing users and their permissions on a Linux system, including `useradd`, `usermod`, `userdel`, and `chown`.

---

#### `useradd`

The `useradd` command adds a new user to the system.

**Basic usage:**

```bash
sudo useradd fgarcia
```

**Common options:**

- `-g`: Sets the primary group

  ```bash
  sudo useradd -g security fgarcia
  ```

- `-G`: Adds to supplemental groups (comma-separated)

  ```bash
  sudo useradd -G finance,admin fgarcia
  ```

---

#### `usermod`

The `usermod` command modifies an existing user account.

**Change primary group:**

```bash
sudo usermod -g executive fgarcia
```

**Add to a supplemental group (without replacing current groups):**

```bash
sudo usermod -a -G marketing fgarcia
```

> ⚠️ If `-a` is not used with `-G`, existing supplemental groups will be replaced.

**Other useful options:**

- `-d`: Change home directory

  ```bash
  sudo usermod -d /home/garcia_f fgarcia
  ```

- `-l`: Change login name
- `-L`: Lock the account to prevent login

  ```bash
  sudo usermod -L fgarcia
  ```

---

#### `userdel`

The `userdel` command removes a user from the system.

**Delete a user (without removing home files):**

```bash
sudo userdel fgarcia
```

**Delete a user and their home directory:**

```bash
sudo userdel -r fgarcia
```

> 🔒 Instead of deleting, you can lock the account:

```bash
sudo usermod -L fgarcia
```

This is useful for deactivating users while retaining access to their files and permissions.

---

#### `chown`

The `chown` command changes file or directory ownership.

**Change file owner:**

```bash
sudo chown fgarcia access.txt
```

**Change group owner:**

```bash
sudo chown :security access.txt
```

> You must prefix the group name with a colon (`:`) when only changing the group.

---

### Help in Linux

**apropos** Searches the manual page descriptions for a specified string.
`bash apropos password` -> searches the manual page descriprions for the word password

## Module 4: Databases and SQL

### Querying a Database (SQL Summary)

- **`SELECT` and `FROM`** are the foundation of any SQL query:

  ```sql
  SELECT customerid, city FROM customers;
  ```

- **`SELECT *`** returns all columns, but it’s better to specify columns in large datasets for clarity and performance.

- **`ORDER BY`** is used to sort results:

  - By default, sorts in **ascending** order.
  - Use `DESC` to sort in **descending** order.

  ```sql
  SELECT customerid, city FROM customers ORDER BY city DESC;
  ```

- **Sorting by multiple columns** is also supported:

  ```sql
  SELECT * FROM customers ORDER BY country, city;
  ```

- The examples use the **Chinook database**, which includes tables like `employees`, `customers`, and `invoices`.

### Filtering Data in SQL (Security Context)

Filtering is essential for analyzing large datasets like security logs, helping you focus on relevant data such as specific users, timestamps, or software versions.

---

#### `WHERE` Clause

- Use `WHERE` to filter rows based on specific conditions:

  ```sql
  SELECT * FROM employees WHERE title = 'IT Staff';
  ```

- The condition follows the column name and uses operators like `=`.

---

#### Pattern Matching with `LIKE` and Wildcards

When you need more flexible filtering:

- Use `LIKE` with **wildcards**:

  - `%` matches any number of characters
  - `_` matches a single character

**Examples:**

| Pattern | Matches Examples  |
| ------- | ----------------- |
| `'a%'`  | apple, art, a     |
| `'a_'`  | an, as, a1        |
| `'%a%'` | again, back, data |
| `'N_'`  | NY, NV, NS, NT    |

**Query example:**

```sql
SELECT * FROM employees WHERE title LIKE 'IT%';
```

This returns titles like "IT Staff" and "IT Manager".

```sql
SELECT * FROM invoices WHERE state LIKE 'N_';
```

This filters for two-letter state codes starting with "N".

---

### Filtering Numbers and Dates in SQL

As a security analyst, you'll often filter **numeric** and **date/time** data—such as login attempts, timestamps, or data volumes—to investigate events or anomalies.

---

#### Common Comparison Operators

Use these in the `WHERE` clause:

| Operator     | Meaning                             |
| ------------ | ----------------------------------- |
| `<`          | less than _(exclusive)_             |
| `>`          | greater than _(exclusive)_          |
| `=`          | equal to                            |
| `<=`         | less than or equal _(inclusive)_    |
| `>=`         | greater than or equal _(inclusive)_ |
| `<>` or `!=` | not equal to                        |

**Example:**

```sql
SELECT first_name, last_name
FROM employees
WHERE birthdate > '1970-01-01';
```

Returns employees born _after_ Jan 1, 1970.

---

#### Using `BETWEEN` for Ranges

The `BETWEEN` operator is **inclusive**, useful for numeric or date ranges:

```sql
SELECT first_name, last_name
FROM employees
WHERE hire_date BETWEEN '2002-01-01' AND '2003-01-01';
```

Returns employees hired _on or between_ the specified dates.

---

### Logical Operators in SQL (AND, OR, NOT)

Logical operators let you combine or negate conditions in your SQL filters—essential for narrowing down results during security investigations.

---

#### `AND`

Returns results only when **both conditions** are true.

**Example:**

```sql
SELECT first_name, email
FROM customers
WHERE support_rep_id = 5 AND country = 'USA';
```

Use when multiple conditions must be met at once.

---

#### `OR`

Returns results when **either condition** is true.

**Example:**

```sql
SELECT *
FROM customers
WHERE country = 'USA' OR country = 'Canada';
```

Even if both conditions refer to the same column, you must repeat the full condition.

---

#### `NOT`

Returns results where a condition is **not** true.

**Example:**

```sql
SELECT *
FROM customers
WHERE NOT country = 'USA';
```

Equivalent to:

```sql
WHERE country <> 'USA'  -- or  country != 'USA'
```

---

#### Combining Logical Operators

You can combine multiple logical operators to build complex filters.

**Example:**

```sql
SELECT *
FROM customers
WHERE NOT country = 'USA' AND NOT country = 'Canada';
```

Returns customers **not** in either USA **or** Canada.

---

### SQL Joins

#### Inner Join

![alt text](/course4:LinuxAndSQL/resources/inner-join.png)

```SQL
SELECT \*

FROM employees

INNER JOIN machines ON employees.device_id = machines.device_id;
```

#### Left Join

![alt text](/course4:LinuxAndSQL/resources/left-join.png)

```SQL
SELECT *

FROM employees

LEFT JOIN machines ON employees.device_id = machines.device_id;
```

#### Right Join

![alt text](/course4:LinuxAndSQL/resources/right-join.png)

```SQL
SELECT *

FROM employees

RIGHT JOIN machines ON employees.device_id = machines.device_id;
```

#### Full Outer Join

![alt text](/course4:LinuxAndSQL/resources/outer-join.png)

```SQL
SELECT *

FROM employees

FULL OUTER JOIN machines ON employees.device_id = machines.device_id;
```
