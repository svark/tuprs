for i in $@ ; do
  echo :$i \|\> echo %f \> %o \|\> out%b.txt
done
