struct AdvancedPointed {
    int count;
    int flag;
    const char *message;
};

extern int puts(const char *);
volatile int advanced_global = 7;
char advanced_message[] = "Advanced catalog fixture string";
unsigned char advanced_scratch[4096] = {1, 2, 3, 4};

__attribute__((noinline)) int advanced_type_fill(struct AdvancedPointed *p) {
    p->count += p->flag;
    return p->count;
}

__attribute__((noinline)) int advanced_add(int left, int right) {
    int computed = left + right;
    if (computed > advanced_global) {
        computed -= advanced_global;
    } else {
        computed += 3;
    }
    return computed;
}

__attribute__((noinline)) int advanced_secondary(int value) {
    return advanced_add(value, 9) + 1;
}

__attribute__((noinline)) int advanced_disposable(int value) {
    return value * 3;
}

int main(void) {
    struct AdvancedPointed value = {19, 23, advanced_message};
    puts(advanced_message);
    return advanced_secondary(advanced_type_fill(&value)) == 0;
}
