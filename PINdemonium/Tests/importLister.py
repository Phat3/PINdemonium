import idaapi
import idc
from sets import Set
imports = Set()

def imp_cb(ea, name, ord):
  if not name:
    print("%08x: ord#%d" % (ea, ord))
    return True #go to next function
    
  print("Found at %08x %s (ord#%d)" % (ea, name, ord))
  imports.add(name)
  return True



def main():

  if len(idc.ARGV) < 2:
    print("importLister.py  <output_file> \n List in the <output_file> the imports of the exe passed to idaPython ")
    idc.Exit(-1)
  
  outputFile = idc.ARGV[1]

  print("output File "+outputFile)
  outputF = open(outputFile,"w") 

  nimps = idaapi.get_import_module_qty()

  print("Found %d import(s)..." % nimps)

  print(nimps)
  for i in xrange(0, nimps):
    name = idaapi.get_import_module_name(i)
    if not name:
      print("Failed to get import module name for #%d" % i)
      continue
    print("count "+ str(i) +" " + name)
    idaapi.enum_import_names(i, imp_cb)

  for imp in imports:
    outputF.write(str(imp)+"\n")
  print("All done...")
  outputF.close()


idaapi.autoWait()
main()
idc.Exit(0)

