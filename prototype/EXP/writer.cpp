#include <iostream>
#include <stdio.h>
#include "pkg.loginfo.pb.h"
#include "pkg.loginfo.pb.cc"
using namespace std;
int main(){
    pkg::loginfo msg1;
    // msg1.set_age(61);
    msg1.set_email("114514");
    msg1.set_name("adm1n");
    msg1.set_passwd("_y000u_pick_the_true_passwd");
    string str1;
    msg1.SerializeToString(&str1);
    cout << str1;
}