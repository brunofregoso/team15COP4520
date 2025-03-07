#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <cmath>
using namespace std;

char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
int alphabet_size = 72;
/**
string password = nullptr;
*/
bool password_cracked = false;
// Idk, come up with something you may want lol
string password = "";

// DANNY
/**
Spins up num_threads threads to crack a password and returns the computation time in milliseconds.
*/
long timeCrackPassword(int num_threads, string hashed_password);

/**
This represents a thread that will attempt to crack hashed_password starting from start_password to end_password. If it’s correct, update globals. Check the globals to determine if the thread should exit early.
*/
void crackPassword(string hashed_password, string start_password, string end_password);

// BRUNO
/**
Returns an array of start and end passwords for a number of threads, inclusive. Equally spreads the intervals so they’re all the same size
ex:
getPasswordIntervals(1, 1) -> [“A”,”Z”]
getPasswordIntervals(2, 1) -> [“A”,”L”,”Z”]
getPasswordIntervals(1, 2) -> [“A”,”ZZ”]
getPasswordIntervals(2, 2) -> [“A”,”LA”,”ZZ”]
*/




long long getTotalCombinations(int max_password_length){
  long long total = 0;
  for(int i = 1; i <= max_password_length; i++){ //Loop through and get total number for each character length 
    total += pow(72, i); //Store sum 
  }
  return total;
}


string getPasswordFromIndex(long long index, int max_password_length){
  long long start = 0;
  long long combinations = getTotalCombinations(max_password_length);
  for(int i = 1; i <= max_password_length; i++){
    long long combinationsforlengt = pow(72, i);
    if(index < combinationsforlengt + start){
      index -= start;
      string password;
      for(int j = 0; j < i; j++){
        password = alphabet[index % 72] + password;
        index /= 72;
      }
      return password;
    } 
    start += combinationsforlengt;
  }
  return "";
}

vector<string> getPasswordIntervals(int num_threads, int max_password_length){
  vector<string> interval;
  long long combinations = getTotalCombinations(max_password_length);
  long long interval_size = combinations / num_threads;
  for(int i = 0; i <= num_threads; i++){
    long long start = i * interval_size;
    if(start >= combinations){
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
string incrementPassword(string password){
  for(int i = password.size() - 1; i >= 0; i--){
    if(password[i] == 'Z'){
      password[i] = 'A';
    } else {
      password[i]++;
      return password;
    }
  }
  return "A" + password;
}

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

// EVAN

long getMedianTime(vector<DataPoint> data_points)
{
  sort(data_points.begin(), data_points.end(), [](DataPoint a, DataPoint b)
       { return a.time_to_crack < b.time_to_crack; });
  return data_points[data_points.size() / 2].time_to_crack;
}

long runCrackPasswordAndGetMedian(int num_threads, string hashed_password, int num_runs, vector<DataPoint> results)
{
  vector<DataPoint> data_points;
  for (int i = 0; i < num_runs; i++)
  {
    long time = timeCrackPassword(num_threads, hashed_password);
    DataPoint data_point;
    data_point.thread_count = num_threads;
    data_point.time_to_crack = time;
    results.push_back(data_point);
    data_points.push_back(data_point);
  }
  return getMedianTime(data_points);
}

/**
Ternary search the best number of threads. Run timeCrackPassword 3 times and take the median run as the runtime for that thread
*/
DataResult findBestThreadCountForPassword(int max_threads, string hashed_password)
{
  const int NUM_RUNS = 3;
  DataResult result;
  result.hashed_password = hashed_password;
  result.password = password;
  int left = 1;
  int right = max_threads;
  // cache the median time for each thread count
  map<int, long> thread_to_median_time;
  while (left < right)
  {
    const int mid1 = left + (right - left) / 3;
    const int mid2 = right - (right - left) / 3;
    auto it1 = thread_to_median_time.find(mid1);
    auto it2 = thread_to_median_time.find(mid2);
    long median1 = it1 != thread_to_median_time.end() ? it1->second : runCrackPasswordAndGetMedian(mid1, hashed_password, NUM_RUNS, result.all_data_points);
    long median2 = it2 != thread_to_median_time.end() ? it2->second : runCrackPasswordAndGetMedian(mid2, hashed_password, NUM_RUNS, result.all_data_points);
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
Run timeCrackPassword 3 times and take the median run as the runtime for that thread, repeat for all threads in num_threads [1,10,50,100]
*/ 
DataResult crackPasswordForThreadCounts(vector<int> num_threads, string hashed_password)
{
  DataResult result;
  result.hashed_password = hashed_password;
  result.password = password;
  for (int i = 0; i < num_threads.size(); i++)
  {
    int num_thread = num_threads[i];
    long median_time = runCrackPasswordAndGetMedian(num_thread, hashed_password, 3, result.all_data_points);
  }
  return result;
} 

// CONOR
/**
Writes all the data to a CSV file to later be read
*/
void outputDataToCSV(DataResult output, string filename);

/**
Read in file, call findBestThreadCountForPassword and crackPasswordForThreadCounts for each password in the input file.
Save results to an output file.
Arguments: path_to_hashed_passswords_file.txt
*/
int main(int argc, char *argv[]){
  return 0;
};
