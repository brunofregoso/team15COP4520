#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <openssl/sha.h>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace std;

struct DataPoint
{
    int thread_count;
    long time_to_crack;
};

struct DataResult
{
    string hashed_password;
    string password;
    vector<DataPoint> all_data_points;
};

long timeCrackPassword(int num_threads, string hashed_password);
string hashPassword(const string &password);
void crackPassword(string hashed_password, string start_password,
                   string end_password);
vector<string> getPasswordIntervals(int num_threads, int max_password_length);
string incrementPassword(string password);
long long getTotalCombinations(int max_password_length);
string getPasswordFromIndex(long long index, int max_password_length);
long getMedianTime(vector<DataPoint> data_points);
long runCrackPasswordAndGetMedian(int num_threads, string hashed_password,
                                  int num_runs, vector<DataPoint> &results);

char alphabet[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
int alphabet_size = 72;
/**
string password = nullptr;
*/

std::atomic<bool> password_cracked(false);
string password = "";
// DANNY
/**
Spins up num_threads threads to crack a password and returns the computation
time in nanoseconds.
*/

long timeCrackPassword(int num_threads, string hashed_password)
{

    password_cracked = false;
    vector<string> intervals =
        getPasswordIntervals(num_threads, hashed_password.length());
    auto start_time = std::chrono::high_resolution_clock::now();
    vector<thread> threads;
    for (int i = 0; i < num_threads; ++i)
    {
        string start_password = intervals[i];
        string end_password   = intervals[i + 1];
        threads.emplace_back(crackPassword, hashed_password, start_password,
                             end_password);
    }

    for (auto &t : threads)
    {
        t.join();
    }
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(
        end_time - start_time);

    return duration.count();
}
// hashPassword function to hash potential passwords to match with the hashed
// passwords

string hashPassword(const string &password)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password.c_str(), password.size());
    SHA256_Final(hash, &sha256);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}
/**
This represents a thread that will attempt to crack hashed_password starting
from start_password to end_password. If it’s correct, update globals. Check the
globals to determine if the thread should exit early.
*/

void crackPassword(string hashed_password, string start_password,
                   string end_password)
{
    string current_password = start_password;

    while (current_password <= end_password && !password_cracked)
    {

        string candidate_hash = hashPassword(current_password);
        if (candidate_hash == hashed_password)
        {
            password_cracked = true;
            password         = current_password;
            break;
        }
        current_password = incrementPassword(current_password);
    }
}

// BRUNO
/**
Returns an array of start and end passwords for a number of threads, inclusive.
Equally spreads the intervals so they’re all the same size ex:
getPasswordIntervals(1, 1) -> [“A”,”Z”]
getPasswordIntervals(2, 1) -> [“A”,”L”,”Z”]
getPasswordIntervals(1, 2) -> [“A”,”ZZ”]
getPasswordIntervals(2, 2) -> [“A”,”LA”,”ZZ”]
*/

long long getTotalCombinations(int max_password_length)
{
    long long total = 0;
    for (int i = 1; i <= max_password_length; i++)
    { // Loop through and get total number for each character length
        total += pow(72, i); // Store sum
    }
    return total;
}

string getPasswordFromIndex(long long index, int max_password_length)
{
    long long start        = 0;
    long long combinations = getTotalCombinations(max_password_length);
    for (int i = 1; i <= max_password_length; i++)
    {
        long long combinationsforlength = pow(72, i);
        if (index < combinationsforlength + start)
        {
            index -= start;
            string password;
            for (int j = 0; j < i; j++)
            {
                password = alphabet[index % 72] + password;
                index /= 72;
            }
            return password;
        }
        start += combinationsforlength;
    }
    return "";
}

vector<string> getPasswordIntervals(int num_threads, int max_password_length)
{
    vector<string> interval;
    long long combinations  = getTotalCombinations(max_password_length);
    long long interval_size = combinations / num_threads;
    for (int i = 0; i <= num_threads; i++)
    {
        long long start = i * interval_size;
        if (start >= combinations)
        {
            start = combinations - 1;
        }
        interval.push_back(getPasswordFromIndex(start, max_password_length));
    }

    return interval;
}

/**
  Returns the next password for a given password
  “A”-> “B”
    “Z”-> “AA”(assuming alphabet is only uppercase letters)
    “AA”-> “AB”
*/
string incrementPassword(string password)
{
    for (int i = password.size() - 1; i >= 0; i--)
    {
        if (password[i] == 'Z')
        {
            password[i] = 'A';
        }
        else
        {
            password[i]++;
            return password;
        }
    }
    return "A" + password;
}

// EVAN

long getMedianTime(vector<DataPoint> data_points)
{
    sort(data_points.begin(), data_points.end(), [](DataPoint a, DataPoint b)
         { return a.time_to_crack < b.time_to_crack; });
    return data_points[data_points.size() / 2].time_to_crack;
}

long runCrackPasswordAndGetMedian(int num_threads, string hashed_password,
                                  int num_runs, vector<DataPoint> &results)
{
    vector<DataPoint> data_points;
    for (int i = 0; i < num_runs; i++)
    {
        long time = timeCrackPassword(num_threads, hashed_password);
        DataPoint data_point;
        data_point.thread_count  = num_threads;
        data_point.time_to_crack = time;
        results.push_back(data_point);
        data_points.push_back(data_point);
    }
    return getMedianTime(data_points);
}

/**
Ternary search the best number of threads. Run timeCrackPassword 3 times and
take the median run as the runtime for that thread
*/
DataResult findBestThreadCountForPassword(int max_threads,
                                          string hashed_password)
{
    const int NUM_RUNS = 3;
    DataResult result;
    result.hashed_password = hashed_password;
    result.password        = password;
    int left               = 1;
    int right              = max_threads;
    // cache the median time for each thread count
    map<int, long> thread_to_median_time;
    while (left < right)
    {
        const int mid1 = left + (right - left) / 3;
        const int mid2 = right - (right - left) / 3;
        auto it1       = thread_to_median_time.find(mid1);
        auto it2       = thread_to_median_time.find(mid2);
        long median1 =
            it1 != thread_to_median_time.end()
                ? it1->second
                : runCrackPasswordAndGetMedian(mid1, hashed_password, NUM_RUNS,
                                               result.all_data_points);
        long median2 =
            it2 != thread_to_median_time.end()
                ? it2->second
                : runCrackPasswordAndGetMedian(mid2, hashed_password, NUM_RUNS,
                                               result.all_data_points);
        thread_to_median_time[mid1] = median1;
        thread_to_median_time[mid2] = median2;
        if (median1 < median2)
        {
            right = mid2;
        }
        else
        {
            left = mid1;
        }
    }

    return result;
}

/**
Run timeCrackPassword 3 times and take the median run as the runtime for that
thread, repeat for all threads in num_threads [1,10,50,100]
*/
DataResult crackPasswordForThreadCounts(int num_threads, string hashed_password)
{
    DataResult result;
    for (int i = 1; i < num_threads; i++)
    {
        long median_time = runCrackPasswordAndGetMedian(
            num_threads, hashed_password, 3, result.all_data_points);
    }
    result.hashed_password = hashed_password;
    result.password        = password;
    return result;
}

// CONOR
/**
 * void outputDataToCSV(vector<DataResult> output, string filename)
 *
 * @param output
 * @param filename
 *
 * This function takes a vector of DataResults and writes them to a CSV file.
 */
void outputDataToCSV(vector<DataResult> output, string filename)
{
    ofstream file(filename);
    file << "hashed_password,password,thread_count,time_to_crack\n";
    for (long unsigned int i = 0; i < output.size(); i++)
        for (long unsigned int j = 0; j < output[i].all_data_points.size(); j++)
            file << output[i].hashed_password << "," << output[i].password
                 << "," << output[i].all_data_points[j].thread_count << ","
                 << output[i].all_data_points[j].time_to_crack << "\n";
    file.close();
}

/**
 * int main(int argc, char *argv[])
 *
 * @param argc
 * @param argv
 * @return int
 *
 * The main function reads in a file containing plaintext passwords, hashes
 * them, and then attempts to crack them using multiple threads. The results
 * are then written to a CSV file.
 */
int main(int argc, char *argv[])
{
    // TODO: Command line flags for output file name, max threads, etc.
    cout << "Multi-threaded Password Cracker" << endl;
    cout << "COP4520 - Team 15\n" << endl;
    if (argc < 2) // Needs filename for input passwords
    {
        cout << "missing required parameter: file" << endl;
        cout << "usage:\n\t" << argv[0] << " <file>" << endl;
        cout << "\nparameters:\n\t<file>\t\tfile containing plaintext passwords"
             << endl;
        return 1;
    }

    cout << "Reading " << argv[1] << "..." << endl;
    string filename = argv[1];
    ifstream file(filename);
    int max_threads = thread::hardware_concurrency();
    string line;
    vector<string> hashed_passwords;
    vector<DataResult> results;

    if (!file.is_open())
    {
        cout << "could not open file: " << filename << endl;
        return 1;
    }

    // Lets find out how many threads we can optimally use on this system. On
    // some systems, this returns 0 if its not supported (SMT/HT off)
    if (max_threads == 0)
    {
        cout << "Hardware threading not supported" << endl;
        max_threads = 1;
    }
    cout << "Using " << max_threads << " threads" << endl;

    // Read in plaintext passwords and hash them. We don't measure the time to
    // do this as it's not part of the cracking process and is merely a setup
    // step executed on a single thread.
    cout << "Hashing plaintext passwords..." << endl;
    while (getline(file, line))
    {
        string hashed_password = hashPassword(line);
        hashed_passwords.push_back(hashed_password);
    }
    cout << "Hashed " << hashed_passwords.size() << " passwords" << endl;
    file.close();

    // Crack each password and store the results
    cout << "Cracking passwords..." << endl;
    auto start_time = std::chrono::high_resolution_clock::now();
    for (long unsigned int i = 0; i < hashed_passwords.size(); i++)
    {
        // TODO: refactor this to a function
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time);
        long double p = ((i + 1.0) / hashed_passwords.size());
        int w         = 60; // char width
        printf("\r[\e[0;32m%.*s\033[0m%*s\e[0;30m%4.1Lf%%\033[0m] "
               "\e[0;30m( %*ld / %ld @ ~%.2Lf/s; \u0394 %lds)\033[0m",
               (int)(p * w), string(w, '|').c_str(), w - (int)(p * w), "",
               p * 100.0, 1 + (int)log10(hashed_passwords.size()), i + 1,
               hashed_passwords.size(),
               (long double)i / (duration.count() / 1000.0),
               duration.count() / 1000); // progress bar
        fflush(stdout);

        results.push_back(
            crackPasswordForThreadCounts(max_threads, hashed_passwords[i]));
    }
    cout << endl;
    cout << "Cracked " << results.size() << " passwords" << endl;
    cout << "Writing results to output.csv..." << endl;
    outputDataToCSV(results, "output.csv");
    cout << "Done" << endl;

    return 0;
};
