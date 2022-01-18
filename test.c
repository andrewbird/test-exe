
// #include <stdio.h>

char ubuf1[0x7fff];
char ubuf2[0x3fff];

char ibuf[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

int __far x = 1;
int __far *y = &x;

__far void __attribute__ ((noinline)) foo(void) {
  int z;

  __asm__ volatile ("jmp 0f");
  __asm__ volatile (".long 0xefbeadde"); // DEADBEEF
  __asm__ volatile ("0:");
  z = x;
  z++;
}

void __far (*p_foo)(void) = foo;

__attribute__((far_section)) __far void bar(void) {}

int main() {
  int a, b, c;

  a = 1;
  b = 2;
  c = a + b;
  c++;

  foo();
  (*p_foo)();
  bar();

  // printf("Sizes: ubuf1=%6u, ubuf2=%6u\n", sizeof ubuf1, sizeof ubuf2);

  return c;
}
