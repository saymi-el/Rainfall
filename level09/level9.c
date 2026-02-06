// level9 - reconstruction C++ (approximation lisible, fidèle au flux ASM)

#include <cstdlib>
#include <cstring>
#include <unistd.h>

class N {
public:
    // Layout (d'après ASM) :
    // +0x00 : vptr (géré par le compilateur)
    // +0x04 : annotation[100]
    // +0x68 : int n
    char annotation[100];
    int  n;

    // ctor: écrit n, vptr initialisé automatiquement
    explicit N(int value) : n(value) {}

    // vulnérable: copie strlen(s) octets sans borne dans annotation
    void setAnnotation(char *s) {
        size_t len = std::strlen(s);
        std::memcpy(this->annotation, s, len); // pas de '\0' ajouté, pas de check
    }

    // virtuels (vtable[0] = operator+, vtable[1] = operator-)
    virtual int operator+(N &other) { return this->n + other.n; }
    virtual int operator-(N &other) { return this->n - other.n; }
};

int main(int argc, char **argv) {
    if (argc <= 1)
        _exit(1);

    N *obj1 = new N(5);
    N *obj2 = new N(6);

    obj1->setAnnotation(argv[1]);

    // Appel virtuel via vtable[0] dans l'ASM : call *(obj2->vptr[0])
    // Ici, ça correspond à operator+(N&)
    obj2->operator+(*obj1);

    return 0;
}
