/**
 * @Author: Sydney Gibbs, B.S.
 * @Date: 11/15/2023
 * @Purpose: This script was written for a System Security Class taken at SMU during the Fall 2023 semester. It is
 * linked with an assignment where one has to write their own paper on a cyber security topic of their choosing. I
 * chose to write an exploratory paper on simple password cracking methodologies, and write my own implementations to
 * explore how these algorithms work, and discuss the timing, effectiveness, and potential defenses against these forms
 * of attacks. This code has implementations of a brute force attack, dictionary attack, and rainbow table attack. In
 * this repo I have provided some example files to use for the dictionary and rainbow table attacks. As of right now,
 * this script only works with sha256 hashed passwords, but for future works I plan to make other hashing options
 * available for testing.
 *
 * @Arguments
 * -argv[1]: Password Dictionary File Path
 * -argv[2]: Rainbow Table File Path
 * -argv[3]: which algorithm you want to run
 *      -1: Brute Force
 *      -2: Dictionary
 *      -3: Rainbow Table
 * -argv[4]: the password hash for which you are hoping to crack
 *
 * @Assumptions
 * -The Rainbow Table file is in tabular separated format:
 *      HASH_VAL    Password
 *      77af778b51abd4a3c51c5ddd97204a9c3ae614ebccb75a606c3b6865aed6744e    cat
 *      efab38fe0f3ccf140f7c7154de23b916858f7ba38cd91a78463d413f8bfb0cf2    HeresToPa$$ingMyGraduateSchoolClasses@SMU!
 *
 * @References
 * Hashing functionality: https://hashlib2plus.sourceforge.net/
 * Common passwords file: https://github.com/Freeguy1/Wordlistss/tree/master
 */

/**
 * ====================================================================================================================
 * Some password/hash pairs that can be found with the example data
 * Plaintext Password: cat
 * Hash (using sha256): 77af778b51abd4a3c51c5ddd97204a9c3ae614ebccb75a606c3b6865aed6744e
 *
 * PLaintext Password: STARWARS!
 * Hash (using sha256): 40eaec7d77e47ee478361f864a73aa17f56efcea8257d3bde78a87a8edf6b0aa
 *
 * Plaintext Password: HOUSTONTEXAS131
 * Hash (using sha256): 3b313a1f7443927acacc88c9db323ccfce6169ac455b80367311121567e9d761
 * ====================================================================================================================
 *
 * ====================================================================================================================
 * Some password/hash pairs that won't be found with the example data
 * Plaintext Password: tmtciwladitsoylitymssycsyk!
 * Hash (using sha256): 36226a3f31cc4a8b301f168acb0d622337d8d0d611c49861d933473687ab5e03
 *
 * PLaintext Password: HaveYouHeardTheTaleOfDarthPlagueisTheWiseIThoughtNotItsNotAStoryTheJediWouldTellYou123456789
 * Hash (using sha256): 086243efb68c23ddf7f3cab87620c9fdcbb8e921c4bbdc34bb66bd390f98d8d3
 *
 * PLaintext Password: KanjiFromPersona4HasTheB3stCharacterArcByFar2000
 * Hash (using sha256): a5bfd3526fd217c3bb119e5da945fb91281f2df58012c456d31cb81190a42bd3
 * ====================================================================================================================
 */

#include <iostream>
#include <hashlibpp.h>
#include <string>
#include <chrono>
#include <cstdlib>
#include <map>
#include <algorithm>
#include <fstream>
using namespace std;
using namespace std::chrono;

int main(int argc, char * argv[]) {
    hashwrapper * myWrapper = new sha256wrapper(); //wrapper needed to hash plaintext passwords

    //program arguments (outlined above)
    string dictionary_file_path = argv[1];
    string rainbow_table_file_path = argv[2];
    int option = atoi(argv[3]);
    string hashToGuess = argv[4];

    /**
     * BRUTE FORCE SECTION
     */
    if(option == 1) {
        auto start = high_resolution_clock::now();
        string currCombo;
        string currHash;
        for (int i = 32; i <= 126; ++i) { //checking all possible length 1 combinations
            currCombo = char(i);
            currHash = myWrapper->getHashFromString(currCombo);
            if(hashToGuess == currHash)
            {
                cout << "Password Found: " << currCombo << endl << "Hash: " << hashToGuess << endl;
                delete myWrapper;
                return 0;
            }
        }
        cout << "END 1" << endl;
        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<nanoseconds>(stop - start);
        cout << "Time taken: " << duration.count() / 1000000000.0 << " seconds" << endl;

        start = high_resolution_clock::now();
        for (int i = 32; i <= 126; ++i) { //checking all possible length 2 combinations
            for (int j = 32; j <= 126; ++j) {
                currCombo = char(i);
                currCombo += char(j);
                currHash = myWrapper->getHashFromString(currCombo);
                if(hashToGuess == currHash)
                {
                    cout << "Password Found: " << currCombo << endl << "Hash: " << hashToGuess << endl;
                    delete myWrapper;
                    return 0;
                }
            }
        }
        cout << "END 2" << endl;
        stop = high_resolution_clock::now();
        duration = duration_cast<nanoseconds>(stop - start);
        cout << "Time taken: " << duration.count() / 1000000000.0 << " seconds" << endl;

        start = high_resolution_clock::now();
        for (int i = 32; i <= 126; ++i) { //checking all possible length 3 combinations
            for (int j = 32; j <= 126; ++j) {
                for (int k = 32; k <= 126; ++k) {
                    currCombo = char(i);
                    currCombo += char(j);
                    currCombo += char(k);
                    currHash = myWrapper->getHashFromString(currCombo);
                    if(hashToGuess == currHash)
                    {
                        cout << "Password Found: " << currCombo << endl << "Hash: " << hashToGuess << endl;
                        delete myWrapper;
                        return 0;
                    }
                }
            }
        }
        cout << "END 3" << endl;
        stop = high_resolution_clock::now();
        duration = duration_cast<nanoseconds>(stop - start);
        cout << "Time taken: " << duration.count() / 1000000000.0 << " seconds" << endl;

        start = high_resolution_clock::now();
        //for length 4
        for (int i = 32; i <= 126; ++i) { //checking all possible length 4 combinations
            for (int j = 32; j <= 126; ++j) {
                for (int k = 32; k <= 126; ++k) {
                    for (int l = 32; l <= 126; ++l) {
                        currCombo = char(i);
                        currCombo += char(j);
                        currCombo += char(k);
                        currCombo += char(l);
                        currHash = myWrapper->getHashFromString(currCombo);
                        if(hashToGuess == currHash)
                        {
                            cout << "Password Found: " << currCombo << endl << "Hash: " << hashToGuess << endl;
                            delete myWrapper;
                            return 0;
                        }
                    }
                }
            }
        }
        cout << "END 4" << endl;
        stop = high_resolution_clock::now();
        duration = duration_cast<nanoseconds>(stop - start);
        cout << "Time taken: " << duration.count() / 1000000000.0 << " seconds" << endl;

        start = high_resolution_clock::now();
        //for length 5
        for (int i = 32; i <= 126; ++i) { //checking all possible length 5 combinations
            for (int j = 32; j <= 126; ++j) {
                for (int k = 32; k <= 126; ++k) {
                    for (int l = 32; l <= 126; ++l) {
                        for (int m = 32; m <= 126; ++m) {
                            currCombo = char(i);
                            currCombo += char(j);
                            currCombo += char(k);
                            currCombo += char(l);
                            currCombo += char(m);
                            currHash = myWrapper->getHashFromString(currCombo);
                            if(hashToGuess == currHash)
                            {
                                cout << "Password Found: " << currCombo << endl << "Hash: " << hashToGuess << endl;
                                delete myWrapper;
                                return 0;
                            }
                        }
                    }
                }
            }
        }
        cout << "END 5" << endl;
        stop = high_resolution_clock::now();
        duration = duration_cast<nanoseconds>(stop - start);
        cout << "Time taken: " << duration.count() / 1000000000.0 << " seconds" << endl;
        cout << "END Brute Force" << endl;
    }
    /**
     * Dictionary Attack
     */
    else if(option == 2)
    {
        auto start = high_resolution_clock::now();
        ifstream inFS;
        inFS.open(dictionary_file_path);
        if(!inFS.is_open())
        {
            cerr << "ERROR READING DICTIONARY FILE" << endl;
            return 1;
        }
        int counter = 0;
        pair<string, string> myPair;
        // for each password in the dictionary file, hash it and see if it matches the hash you're trying to crack
        while(!inFS.eof())
        {
            string currPwd;
            getline(inFS, currPwd);
            string currHash = myWrapper->getHashFromString(currPwd);
            if(hashToGuess == currHash) {
                cout << "Found matching hash for password: " << currPwd << endl;
                break;
            }
            counter++;
            if(counter % 5000000 == 0) {
                cout << counter << " passwords checked" << endl;
            }
        }
        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<nanoseconds>(stop - start);
        cout << "Time taken to check entire dictionary: " << duration.count() / 1000000000.0 << " seconds" << endl;
        cout << "NUM PASSWORDS: " << counter << endl;
        inFS.close();
    }
    /**
    * Rainbow-Table Attack
    */
    else if (option == 3)
    {
        auto start = high_resolution_clock::now();
        map<string, string> table;
        ifstream inFS;
        inFS.open(rainbow_table_file_path);
        if(!inFS.is_open())
        {
            cerr << "ERROR READING RAINBOW TABLE FILE" << endl;
            return 1;
        }
        int counter = 0;
        pair<string, string> myPair;
        while(!inFS.eof())
        {
            string currPwd;
            string currHash;
            getline(inFS, currHash, '\t');
            getline(inFS, currPwd);
            myPair.first = currHash;
            myPair.second = currPwd;
            table.insert(myPair);
            counter++;
            if(counter % 5000000 == 0) {
                cout << counter << " passwords retrieved" << endl;
            }
        }
        cout << "NUM PASSWORDS: " << counter << endl;
        cout << "MAP SIZE: " << table.size() << endl;
        inFS.close();
        auto stop = high_resolution_clock::now();
        auto duration = duration_cast<nanoseconds>(stop - start);
        cout << "Time taken to build rainbow table: " << duration.count() / 1000000000.0 << " seconds" << endl;

        //time how long it takes to fetch passwords
        string guess = "";
        while(guess != "Q")
        {
            cout << "enter a hash you want to search for in the table (or press Q then enter to quit)" << endl;
            getline(cin, guess);
            start = high_resolution_clock::now();
            if(guess == "Q")
                break;
            auto it = table.find(guess);
            if (it != table.end())
                cout << "Password Found: " << table[guess] << endl << "Hash: " << guess << endl;
            else
                cout << "Hash " << guess << " not found in table :(" << endl;
            stop = high_resolution_clock::now();
            duration = duration_cast<nanoseconds>(stop - start);
            cout << "Time taken to fetch password from rainbow table: " << duration.count() / 1000000000.0 << " seconds" << endl;
        }
    }
    else
        cerr << "Invalid Option" << endl;
    delete myWrapper;
    return 0;
}