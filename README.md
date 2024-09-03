# Elbrus-2000 decodetree generator

Automatically generate [decodetree](https://github.com/numas13/decodetree) file for instructions in ALC for E2K architecture.

```
# build
$ make
# run
$ ./main | tail
{
  qplog_and          ------- -10 00010011........ .0000000........................ @alf21_lt3 ? v7 alias
  qplog_xor          ------- -10 00010011........ .0010110........................ @alf21_lt3 ? v7 alias
  qplog_sel3         ------- -10 00010011........ .1011000........................ @alf21_lt3 ? v7 alias
  qplog_mjr          ------- -10 00010011........ .1101000........................ @alf21_lt3 ? v7 alias
  qplog_or           ------- -10 00010011........ .1111110........................ @alf21_lt3 ? v7 alias
  qplog              ------- -10 0001001......... ................................ @alf21_log_lt3 ? v7
}
qpinss               ------- -0- 00010111........ .0101100........................ @alf21_lt3 ? v7
qpinsd               ------- -0- 00010111........ .0101101........................ @alf21_lt3 ? v7
```
