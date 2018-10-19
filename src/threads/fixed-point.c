#include <stdio.h>
#include <inttypes.h>
int f = 16384;
int integer_to_fixed_point(int n){
return n*f;
}
int divide(int x, int y){
return ((int64_t)x)*f/y;
}
int multiply(int x, int y){
   return ((int64_t)x)*y/f;
}
int fixed_point_to_integer(int n){
    return n/f;

}
int main(){
int f1 = integer_to_fixed_point(360);
int f1Square = multiply(f1,f1);
int x = fixed_point_to_integer(f1Square);
printf("\n%d %d %d \n",f1,f1Square,x);
return 0;
}
