import idaapi
import idc


if len(idc.ARGV) < 3:
  print idc.ARGV[0]+"  <inputFile> <outputFile>"
  idc.Exit(-1)
  
inputFile = idc.ARGV[1]
outputFile = idc.ARGV[2]
initFunc = []
print "input File "+inputFile
print "output File "+outputFile
outputF = open(outputFile,"w") 

def imp_cb(ea, name, ord):
  for func in initFunc:
    if not name:
      print "%08x: ord#%d" % (ea, ord)
      return True #go to next function
    if name == func:
      print "Found at %08x %s (ord#%d)" % (ea, func, ord)
      outputF.write(hex(ea)+","+func+","+str(ord)+"\n")
  return True

def loadInitFunc():
  with open(inputFile) as f:
    for line in f:
      initFunc.append(line.rstrip())
  print "Loaded functions %s" % initFunc 


def main():

  print "AAAAAAAAAAAAAAAAAAAAA"
  loadInitFunc()
  nimps = idaapi.get_import_module_qty()

  print "Found %d import(s)..." % nimps

  for i in xrange(0, nimps):
    name = idaapi.get_import_module_name(i)
    if not name:
      print "Failed to get import module name for #%d" % i
      continue
    idaapi.enum_import_names(i, imp_cb)

  print "All done..."
  outputF.close()

idaapi.autoWait()
main()
idc.Exit(0)

