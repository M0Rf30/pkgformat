/* Prints what glibc answers for the expression matching of apt's pin code.
 *
 * Every line of the standard input is "kind<TAB>pattern<TAB>string"; kind is
 * "glob" (fnmatch with FNM_CASEFOLD) or "regex" (regcomp with REG_EXTENDED and
 * REG_ICASE, then regexec, as pkgVersionMatch::ExpressionMatches does with the
 * pattern between slashes). The answer is appended as a fourth column: 1, 0,
 * or "invalid" for a regular expression regcomp rejects.
 *
 * The first three columns of matchvec.tsv are the inputs:
 *
 *   cc -o matchvec matchvec.c && cut -f1-3 matchvec.tsv | ./matchvec
 */
#define _GNU_SOURCE
#include <fnmatch.h>
#include <locale.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
   /* apt runs under the user's UTF-8 locale; multibyte characters are one unit. */
   if (!setlocale(LC_ALL, "C.UTF-8"))
      return 1;
   char line[4096];
   while (fgets(line, sizeof line, stdin))
   {
      size_t n = strlen(line);
      if (n && line[n - 1] == '\n')
	 line[--n] = 0;
      char *kind = line;
      char *pattern = strchr(kind, '\t');
      if (!pattern)
	 continue;
      *pattern++ = 0;
      char *str = strchr(pattern, '\t');
      if (!str)
	 continue;
      *str++ = 0;

      const char *answer;
      if (strcmp(kind, "glob") == 0)
	 answer = fnmatch(pattern, str, FNM_CASEFOLD) == 0 ? "1" : "0";
      else
      {
	 regex_t re;
	 if (regcomp(&re, pattern, REG_EXTENDED | REG_ICASE) != 0)
	    answer = "invalid";
	 else
	 {
	    answer = regexec(&re, str, 0, NULL, 0) == 0 ? "1" : "0";
	    regfree(&re);
	 }
      }
      printf("%s\t%s\t%s\t%s\n", kind, pattern, str, answer);
   }
   return 0;
}
