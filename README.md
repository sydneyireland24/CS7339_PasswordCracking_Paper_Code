# CS7339_PasswordCracking_Paper_Code

## Instructions for Use
This script was written for a System Security Class taken at SMU during the Fall 2023 semester. It is linked with an assignment where one has to write their own paper on a cyber security topic of their choosing. I chose to write an exploratory paper on simple password cracking methodologies, and write my own implementations to explore how these algorithms work, and discuss the timing, effectiveness, and potential defenses against these forms of attacks. This code has implementations of a brute force attack, dictionary attack, and rainbow table attack. In this repo I have provided some example files to use for the dictionary and rainbow table attacks. As of right now, this script only works with sha256 hashed passwords, but for future works I plan to make other hashing options available for testing.

### Arguments
-argv[1]: Password Dictionary File Path
-argv[2]: Rainbow Table File Path
-argv[3]: which algorithm you want to run
      -1: Brute Force
      -2: Dictionary
      -3: Rainbow Table
-argv[4]: the password hash for which you are hoping to crack

### Assumptions
-The Rainbow Table file is in tabular separated format:
      HASH_VAL    Password
      77af778b51abd4a3c51c5ddd97204a9c3ae614ebccb75a606c3b6865aed6744e    cat
      efab38fe0f3ccf140f7c7154de23b916858f7ba38cd91a78463d413f8bfb0cf2    HeresToPa$$ingMyGraduateSchoolClasses@SMU!
      etc.

## Dependencies
-C++ version 11 or greater
-hashlib2plus

## References
-Hashing functionality: https://hashlib2plus.sourceforge.net/
-Common passwords file: https://github.com/Freeguy1/Wordlistss/tree/master
