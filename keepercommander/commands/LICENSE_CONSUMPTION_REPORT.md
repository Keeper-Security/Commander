# License Consumption Report

## Overview

The `license-consumption-report` command helps enterprise administrators identify which users are consuming feature licenses based on role enforcement policies. This addresses the common need to understand license utilization for compliance, budgeting, and license management purposes.

## How It Works

### Enforcement Policy Detection

The report works by:

1. **Analyzing Role Enforcements**: Examines all enterprise roles and their enforcement policies
2. **Categorizing by Feature**: Groups enforcement policies by feature type (PAM, Secrets Manager, etc.)
3. **Finding Feature Users**: Identifies users assigned to roles that have feature-specific enforcements enabled
4. **Team Resolution**: Optionally includes users assigned to roles through team membership

## Usage Examples

### Basic PAM License Report
```bash
keeper license-consumption-report --feature pam
```
Shows all users with PAM enforcement policies enabled. By default, shows feature counts only.

### Show Detailed Feature Names
```bash
keeper license-consumption-report --feature pam --details
```
Shows the specific feature names instead of just counts (useful for detailed analysis).

### All Features Consolidated Report
```bash
keeper license-consumption-report --feature all
```
Shows license consumption across all feature types in a single report with separate columns for each feature.

### Include Team Assignments
```bash
keeper license-consumption-report --feature pam --include-teams
```
Also includes users who get PAM access through team membership in roles with PAM policies.

### Filter by Organization Node
```bash
keeper license-consumption-report --feature pam --node "Engineering"
```
Limits results to users in the "Engineering" node and its descendants.

### Export Results
```bash
keeper license-consumption-report --feature pam --format csv --output pam_licenses.csv
```
Exports results in CSV format for further analysis in spreadsheet applications.

### Comprehensive Analysis Examples
```bash
# All features with detailed breakdown
keeper license-consumption-report --feature all --details --include-teams

# PAM users with details, including teams, export to CSV
keeper license-consumption-report --feature pam --details --include-teams --format csv --output pam_detailed.csv

# Quick overview of all license consumption
keeper license-consumption-report --feature all
```

### Individual Feature Types
```bash
keeper license-consumption-report --feature secrets-manager
keeper license-consumption-report --feature connection-manager
keeper license-consumption-report --feature breachwatch
```

## Report Output

### Columns Included

#### Single Feature Reports
| Column | Description |
|--------|-------------|
| Username | User's email address |
| Display Name | User's full name |
| Node | Organization node path |
| Status | User account status |
| Direct Roles | Roles directly assigned to user |
| Team Roles | Roles assigned through team membership |
| [FEATURE] Features | Feature count by default, detailed names with `--details` |
| Feature Count* | Number of feature enforcement policies |

*Feature Count column only appears when NOT using `--details` (to avoid redundancy)

#### All Features Report
| Column | Description |
|--------|-------------|
| Username | User's email address |
| Display Name | User's full name |
| Node | Organization node path |
| Status | User account status |
| Direct Roles | Roles directly assigned to user |
| Team Roles | Roles assigned through team membership |
| Pam Features* | PAM feature details (if `--details` flag used) |
| Pam Count** | Number of PAM features |
| Secrets Manager Count** | Number of Secrets Manager features |
| Connection Manager Count** | Number of Connection Manager features |
| Breachwatch Count** | Number of BreachWatch features |
| Total Features | Sum of all feature counts (always shown) |

*Feature detail columns only appear when using `--details` flag  
**Individual count columns only appear when NOT using `--details` (to avoid redundancy)

### Sample Output

#### Default Output (Feature Counts Only)
```
PAM License Consumption Report - 15 Users Found

Username              Display Name    Node         Status  Direct Roles    Team Roles           PAM Features    Feature Count
john.doe@company.com  John Doe       Engineering  Active  PAM Admin       IT Team -> PAM User  2 feature(s)    2
jane.smith@company.com Jane Smith     IT           Active                  DevOps -> PAM Role   1 feature(s)    1
```

#### With --details Flag (No Redundant Count Column)
```
PAM License Consumption Report - 15 Users Found

Username              Display Name    Node         Status  Direct Roles    Team Roles           PAM Features
john.doe@company.com  John Doe       Engineering  Active  PAM Admin       IT Team -> PAM User  PAM Gateway, Configure RBI
jane.smith@company.com Jane Smith     IT           Active                  DevOps -> PAM Role   Launch PAM Tunnels
```

#### All Features Report (Default - Counts Only)
```
All Features License Consumption Report - 15 Users Found

Username              Display Name    Node         Status  Direct Roles    Pam Count  Secrets Manager Count  Connection Manager Count  Breachwatch Count  Total Features
john.doe@company.com  John Doe       Engineering  Active  PAM Admin       10         1                      1                         0                  12
jane.smith@company.com Jane Smith     IT           Active  DevOps          0          1                      0                         1                  2
```

#### All Features Report (With --details - No Redundant Count Columns)
```
All Features License Consumption Report - 15 Users Found

Username              Display Name    Node         Status  Direct Roles    Pam Features                         Secrets Manager Features    Total Features
john.doe@company.com  John Doe       Engineering  Active  PAM Admin       PAM Gateway, Configure RBI, ...      Secrets Manager              12
jane.smith@company.com Jane Smith     IT           Active  DevOps                                               Secrets Manager              2
```

## This Report Addresses the Following Questions:

### ✅ **"Which users are consuming PAM licenses?"**
The report identifies all users with any of the 13 PAM enforcement checkboxes enabled in their roles.

### ✅ **"No simple command in commander"** 
Now available as `license-consumption-report` with alias `lcr`.

### ✅ **"Users from teams assigned to roles"**
The `--include-teams` flag captures users who get PAM access through team membership.

### ✅ **"Unique users from all roles"**
Automatically deduplicates users who appear in multiple roles or teams.

### ✅ **"Format option for enterprise-team"**
Provides CSV, JSON, and other output formats for analysis.

## Command Alias

The command is available as both:
- `license-consumption-report` (full name)
- `lcr` (alias for quick access)

### Quick Examples with Alias
```bash
# Quick PAM report with counts only
lcr --feature pam

# All features overview  
lcr --feature all

# Detailed PAM report including teams
lcr --feature pam --details --include-teams
```