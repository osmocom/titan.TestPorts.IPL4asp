#!/bin/sh


if [ $# -eq 2 ]
then

cat IPL4asp_PortType.ttcn | sed '
s/IPL4asp_PortType/IPL4asp_User_CtrlFunc/g
/type port IPL4asp_PT/,/\"provider\"}/ s/.*//g
s/IPL4asp_PT/'$2'/g
/\/\*/,/\*\// s/.*//g
/^$/ d
s/import from IPL4asp_Types all;/import from '$1' all;\n  import from IPL4asp_Types all;/
' > IPL4asp_User_CtrlFunct.temp

cat IPL4asp_PT.cc | sed '
s/IPL4asp__PortType/IPL4__User__CtrlFunc/g
s/IPL4asp_PT.cc/IPL4asp_User_CtrlFuncDef.ttcn/g
s/IPL4asp__PT/'$1'::'$2'/g
/#define SET_OS_ERROR_CODE/,/} \/\/ f__IPL4__PROVIDER__getConnectionDetails/ s/.*//
/^$/ d 
/#include </d 
s/#include \"IPL4asp_PT.hh\"/#include \"'$1'.hh\"\n#include \"IPL4asp_PT.hh\"/
s/Result/IPL4asp__Types::Result/g
s/const /const IPL4asp__Types::/g
' > IPL4asp_User_CtrlFunctDef.temp

mv IPL4asp_User_CtrlFunct.temp IPL4asp_User_CtrlFunct.ttcn
mv IPL4asp_User_CtrlFunctDef.temp IPL4asp_User_CtrlFunctDef.cc


else
    echo "Usage: generate_control_functs.sh <user types module> <user port type> " 
fi


