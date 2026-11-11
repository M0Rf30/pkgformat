// Prints, for every "source<TAB>source-version<TAB>machine-id" line of the
// standard input, what apt computes for a phased update with libstdc++:
//
//   seed words   the four words std::seed_seq::generate produces (hex)
//   draw99       std::uniform_int_distribution<unsigned>(0, 99) of std::minstd_rand
//   draw100      the same over 0..100
//
// The seed string is "<source>-<source-version>-<machine-id>" as in apt-pkg's
// policy.cc. Build and run: g++ -O1 -o draw draw.cc && ./draw < inputs.txt
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

int main()
{
   std::string line;
   while (std::getline(std::cin, line))
   {
      std::vector<std::string> f;
      std::stringstream ss(line);
      std::string part;
      while (std::getline(ss, part, '\t'))
	 f.push_back(part);
      if (f.size() != 3)
	 continue;

      std::string seedStr = f[0] + "-" + f[1] + "-" + f[2];

      std::seed_seq words(seedStr.begin(), seedStr.end());
      uint32_t arr[4];
      words.generate(arr, arr + 4);

      std::seed_seq seed99(seedStr.begin(), seedStr.end());
      std::minstd_rand rand99(seed99);
      std::uniform_int_distribution<unsigned int> dist99(0, 99);
      unsigned d99 = dist99(rand99);

      std::seed_seq seed100(seedStr.begin(), seedStr.end());
      std::minstd_rand rand100(seed100);
      std::uniform_int_distribution<unsigned int> dist100(0, 100);
      unsigned d100 = dist100(rand100);

      printf("%s\t%s\t%s\t%08x%08x%08x%08x\t%u\t%u\n", f[0].c_str(), f[1].c_str(), f[2].c_str(),
	     arr[0], arr[1], arr[2], arr[3], d99, d100);
   }
}
