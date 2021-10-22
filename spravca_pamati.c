#include <stdio.h>
#include <string.h>

// obsahuje bloky volnej pamate
typedef struct mem_block {
	unsigned int size;
	struct mem_block *next;	
} MEM_BLOCK;


void *memory_alloc(unsigned int size);
int memory_free(void *valid_ptr);
int memory_check(void *ptr);
void memory_init(void *ptr, unsigned int size);

int add_block(MEM_BLOCK * to_add);
void delete_block(MEM_BLOCK * to_del);
int merge_blocks();
MEM_BLOCK *split_block(MEM_BLOCK *to_split, unsigned int size);

// pointer na pamat, ktora vstupuje do memory_init(). Ukazuje na zaciatok volnej pamate.
MEM_BLOCK *head_ptr = NULL;


// funkcia, ktora alokuje pamat pre danu velkost.......................................................................
void *memory_alloc(unsigned int size) {
	void *allocated_ptr = NULL;	// pointer, ktory ukazuje na blok alokovanej pamate
	MEM_BLOCK *temp = head_ptr,
		      *excess = NULL;	// prebytocna pamat, ktora vznika ak alokujeme privelky blok

	if (size == NULL)
		return NULL;
	
	while (temp != NULL) {
		// tento kod prebehne, ked najdeme volny blok pamate, ktory je rovnako velky ako ten, ktory chceme alokovat.
		if (temp->size == size) {
			allocated_ptr = ((void *)((long)temp + sizeof(head_ptr->size)));
			delete_block(temp);
			return allocated_ptr;
		}
		/* Tento kod prebehne, ked najdeme volny blok pamate, ktory je vacsi ako ten, ktory chceme alokovat.
		Kedze blok je vacsi ako potrebujeme, tak ho rozdelime a nadbytocnu cast presunieme do listu, ktory obsahuje volne bloky. */
		else if (temp->size > size) {
			allocated_ptr = ((void *)((long)temp + sizeof(head_ptr->size)));
			if ((size + sizeof(MEM_BLOCK)) < temp->size) {
				excess = split_block(temp, size); // rozdelime blok, ktory je nadbytocne velky
				add_block(excess); // nadbytocnu cast pridavame do zoznamu volnych blokov
			}
			delete_block(temp); // vymaze blok z listu volnych blokov
			return allocated_ptr;
		}
		// ak aktualny blok nie je dostatocne velky, tak sa presunieme na dalsi.
		else
			temp = temp->next;
	}
	// ak sa nenajde dostatocne velky blok, tak nam funkcia vrati NULL pointer.
	printf("Nie je k dispozicii dostatocne velky pamatovy blok... :(\n");
	return NULL;

}


// funkcia, ktora uvolni alokovanu pamat. Vrati nulu, ak vsetko prebehlo uspesne, inac vracia 1........................
int memory_free(void *valid_ptr) {
	MEM_BLOCK *free = NULL;

	free = ((void *)((long)valid_ptr - sizeof(free->size))); // pozicia, kde sa zacina dany blok 

	// ak vsetko prebehlo uspesne (blok sa podarilo vratit a volne bloky za sebou sa pospajali), tak funkcia vrati 0
	if ((add_block(free) == 1) && (merge_blocks() == 1)) {
		merge_blocks(); 
		return 0;
	}
	else
		return 1;
}


// funkcia, ktora inicializuje pamat, ktoru budeme moct vyuzit k alokacii..............................................
void memory_init(void *ptr, unsigned int size) {

	head_ptr = ptr;	// nastavi globalny pointer na zaciatok pola
	head_ptr->next = NULL;	// nastavi nasledujuci volny blok na NULL
	head_ptr->size = size;	// nastavi velkost urcenu k alokacii na size
}


// funkcia kontroluje, ci pointer bol alokovany a nie este uvolneny. Vracia 1 ak bol alokovany, inac vrati 0...........
// asi nefunguje lol
int memory_check(void *ptr) {
	MEM_BLOCK *temp = head_ptr;
	MEM_BLOCK *to_check = (void *)ptr;

	if (to_check < head_ptr) {
		return 1;
	}

	while (temp->next != NULL) {
		if (((long)temp + temp->size + sizeof(temp->size)) < (long)to_check && (long)to_check < (long)temp->next) {

			while (temp < to_check) {
				if ((long)temp + sizeof(temp->size) == (long)to_check) {
					return 1;
				}
				(long)temp += temp->size;
				(long)temp += sizeof(temp->size);
				if (temp > to_check) {
					return 0;
				}
			}
			return 0;
		}
		temp = temp->next;
	}
	return 0;
}



// funkcia, ktora prida volny blok do zoznamu. Udrzuje poradie blokov podla adries, aby sa lahsie spajali..............
int add_block(MEM_BLOCK * to_add) {
	MEM_BLOCK *temp = head_ptr;

	to_add->next = NULL;
	
	// Tato cast kodu prebehne, ak head_ptr je NULL, alebo je umiestneny dalej v pamati, ako blok, co pridavame.
	if (head_ptr == NULL || (head_ptr > to_add)) {
		to_add->next = head_ptr;	// pridavany blok smeruje na terajsi head_ptr
		head_ptr = to_add;	// nastavime pridavany blok ako head pointer
		return 1;
	}
	// Tato cast kodu prebehne, ak head_ptr nie je NULL, alebo je umiestneny v pamati pred blokom co pridavame.
	else if (head_ptr != NULL || (head_ptr < to_add)) {
		while (temp->next != NULL && (temp->next < to_add)) // cyklus hlada blok, ktory sa nachadza pred pridavanym blokom
			temp = temp->next;
		to_add->next = temp->next;	// pridavany blok smeruje dalej na blok za predchadzajucim
		temp->next = to_add;	// predchadzajuci blok smeruje dalej na pridavany blok	
		return 1;
	}
	else
		return 0;
}


// funkcia, ktora odstranuje blok zo zoznamu volnych blokov............................................................
void delete_block(MEM_BLOCK *to_del) {
	MEM_BLOCK *prev = head_ptr;
	
	
	if (to_del->next != NULL){
		// ak sa head_ptr nachadza pred blokom, ktory vymazavame, tak zostava rovnaky
		if (head_ptr < to_del) {
			head_ptr = head_ptr;
		}
		// ak sa head_ptr nenachadza pred blokom, ktory vymazavame, tak sa posunie na nasledujuci
		else {
			head_ptr = to_del->next;
		}
		// najde blok, ktory sa nachadza pred blokom, ktory chceme vymazat
		while (prev->next != NULL && prev->next < to_del) {
			prev = prev->next;
		}
		prev->next = to_del->next;	// predchadzajuci blok nasmerujeme na blok za vymazanym
		to_del->next = NULL;	// vymazany blok nasmerujeme na NULL
	}
	else {
		head_ptr = NULL;
	}
}


// funkcia, ktora rozdeli nadbytocne velky blok a vrati pointer ukazujuci na prebytocnu cast...........................
MEM_BLOCK *split_block(MEM_BLOCK *to_split, unsigned int size) {
	MEM_BLOCK *excess_block;


	if (size > sizeof(MEM_BLOCK) - sizeof(to_split->size)) {
		excess_block = ((long)to_split + size + sizeof(to_split->size));
		excess_block->size = to_split->size - (size + sizeof(to_split->size));
		to_split->size = size;
	}
	else {
		excess_block = ((long)to_split + sizeof(MEM_BLOCK));
		excess_block->size = to_split->size - sizeof(MEM_BLOCK);
		to_split->size = sizeof(MEM_BLOCK) - sizeof(to_split->size);
	}
	return excess_block;
}


// funkcia, ktora prechadza cez list a ak ma moznost, tak spaja susedne volne bloky....................................
int merge_blocks() {
	MEM_BLOCK *temp = head_ptr;
	
	while (temp->next != NULL) {
		/* Ak za sebou nasleduju dva volne bloky, tak sa spoja do jedneho, ich velkosti sa zrataju a
		novovytvoreny spojeny blok vytvori spojenie s nasledujucim volnym blokom. */
		if ((long)temp + temp->size + sizeof(temp->size) == (long)temp->next) {
			temp->size += temp->next->size + sizeof(temp->size);
			temp->next = temp->next->next;
			// Ak novovytvoreny blok smeruje dalej na NULL, tak funkcia moze uspesne skoncit
			if (temp->next == NULL)
				return 1;
		}
		temp = temp->next;
		if (temp->next == NULL)
			return 1;
	}
	return 1;
}



// main................................................................................................................
int main() {
	char array[100];

	memory_init(array, 100);
	
	// Testovacie vstupy
	/*printf("%p\n", head_ptr);
	int *a = (int *)memory_alloc(sizeof(int));
	memset(a, 'a', sizeof(int));
	int *b = (int *)memory_alloc(sizeof(int));
	memset(b, 'b', sizeof(int));
	int *c = (int *)memory_alloc(sizeof(int));
	memset(c, 'c', sizeof(int));
	int *d = (int *)memory_alloc(sizeof(int));
	memset(d, 'd', sizeof(int));
	int *e = (int *)memory_alloc(sizeof(int));
	memset(e, 'e', sizeof(int));
	int *f = (int *)memory_alloc(sizeof(int));
	memset(f, 'f', sizeof(int));
	
	memory_free(e);
	memory_free(d);

	printf("A B C F alokovane E D volne\n");
	printf("A vibe check %d \n", memory_check(a));
	printf("B vibe check %d \n", memory_check(b));
	printf("C vibe check %d \n", memory_check(c));
	printf("D vibe check %d \n", memory_check(d));
	printf("E vibe check %d \n", memory_check(e));
	printf("F vibe check %d \n", memory_check(f));

	memory_free(a);

	printf("B C F alokovane A E D volne\n");
	printf("A vibe check %d \n", memory_check(a));
	printf("B vibe check %d \n", memory_check(b));
	printf("C vibe check %d \n", memory_check(c));
	printf("D vibe check %d \n", memory_check(d));
	printf("E vibe check %d \n", memory_check(e));
	printf("F vibe check %d \n", memory_check(f));*/

	/*int x = 0;
	printf("X vibe check %d \n", memory_check(x));
	int w = 1;
	printf("W vibe check %d \n", memory_check(w));
	int y = 5;
	printf("Y vibe check %d \n", memory_check(y));*/

	/*printf("%p\n", head_ptr);
	int *a = (int *)memory_alloc(sizeof(int));
	memset(a, 'a', sizeof(int));
	printf("%p\n", head_ptr);
	int *b = (int *)memory_alloc(sizeof(int));
	memset(b, 'b', sizeof(int));
	printf("%p\n", head_ptr);
	int *c = (int *)memory_alloc(sizeof(int));
	memset(c, 'c', sizeof(int));
	int *d = (int *)memory_alloc(sizeof(int));
	memset(d, 'd', sizeof(int));
	printf("%p\n", head_ptr);
	int *e = (int *)memory_alloc(sizeof(int));
	memset(e, 'e', sizeof(int));
	printf("%p\n", head_ptr);
	int *f = (int *)memory_alloc(sizeof(int));
	memset(f, 'f', sizeof(int));
	int *g = (int *)memory_alloc(sizeof(int));
	memset(g, 'g', sizeof(int));
	printf("%p\n", head_ptr);
	int *h = (int *)memory_alloc(sizeof(int));
	memset(h, 'h', sizeof(int));
	printf("%p\n", head_ptr);
	int *i = (int *)memory_alloc(sizeof(int));
	memset(i, 'i', sizeof(int));
	int *j = (int *)memory_alloc(sizeof(int));
	memset(j, 'j', sizeof(char));
	printf("%p\n", head_ptr);
	int *k = (int *)memory_alloc(sizeof(int));
	memset(k, 'k', sizeof(int));
	//int *l = (int *)memory_alloc(sizeof(int));
	//memset(l, 'l', sizeof(int));*/

	int *a = (int *)memory_alloc(sizeof(int));
	int *b = (int *)memory_alloc(sizeof(int));
	int *c = (int *)memory_alloc(sizeof(int));
	int *d = (int *)memory_alloc(sizeof(int));
	int *e = (int *)memory_alloc(sizeof(int));

	memset(a, 'a', sizeof(int));
	memset(b, 'b', sizeof(int));
	memset(c, 'c', sizeof(int));
	memset(d, 'd', sizeof(int));
	memset(e, 'e', sizeof(int));

	printf("A B C D E alokovane\n");
	printf("A  check %d \n", memory_check(a));
	printf("B  check %d \n", memory_check(b));
	printf("C  check %d \n", memory_check(c));
	printf("D  check %d \n", memory_check(d));
	printf("E  check %d \n", memory_check(e));

	if (memory_free(a) == 0);	
	if (memory_free(c) == 0);
	if (memory_free(d) == 0);	

	int *x = (int *)memory_alloc(2 * sizeof(int));
	memset(x, 'x', 2 * sizeof(int));
	printf("X E B alokovane A C D free\n");
	printf("X  check %d \n", memory_check(x));
	printf("E  check %d \n", memory_check(e));
	printf("B  check %d \n", memory_check(b));
	printf("A  check %d \n", memory_check(a));
	printf("D  check %d \n", memory_check(d));
	printf("C  check %d \n", memory_check(c));
	if (memory_free(x) == 0);
	
	printf("E B alokovane A C D X free\n");
	printf("X  check %d \n", memory_check(x));
	printf("E  check %d \n", memory_check(e));
	printf("C  check %d \n", memory_check(c));
	printf("B  check %d \n", memory_check(b));
	printf("A  check %d \n", memory_check(a));
	printf("D  check %d \n", memory_check(d));

	if (memory_free(b) == 0);
	if (memory_free(e) == 0);

	printf("A B D C D E X free\n");
	printf("A  check %d \n", memory_check(a));
	printf("B  check %d \n", memory_check(b));
	printf("D  check %d \n", memory_check(d));
	printf("X  check %d \n", memory_check(x));
	printf("E  check %d \n", memory_check(e));
	printf("C  check %d \n", memory_check(c));
	
	/*printf("FIRST HEAD %p\n", head_ptr);

	char *a = (char *)memory_alloc(520 * sizeof(char));
	char *b = (char *)memory_alloc(666 * sizeof(char));
	char *c = (char *)memory_alloc(1204 * sizeof(char));
	char *d = (char *)memory_alloc(805 * sizeof(char));
	char *e = (char *)memory_alloc(5393 * sizeof(char));

	memory_free(e);
	memory_free(b);
	memory_free(a);

	printf("C D alokovane A B free\n");
	printf("B vibe check %d \n", memory_check(b));
	printf("A vibe check %d \n", memory_check(a));
	printf("D vibe check %d \n", memory_check(d));
	printf("C vibe check %d \n", memory_check(c));

	char *f = (char *)memory_alloc(666 * sizeof(char));
	char *i = (char *)memory_alloc(145 * sizeof(char));
	char *g = (char *)memory_alloc(14502 * sizeof(char));
	char *h = (char *)memory_alloc(4207 * sizeof(char));

	printf("A %p\n", a);
	printf("B %p\n", b);
	printf("C %p\n", c);
	printf("F %p\n", f);
	printf("I %p\n", i);
	printf("H %p\n", h);

	printf("F I G alokovane A B free\n");
	printf("B vibe check %d \n", memory_check(b));
	printf("A vibe check %d \n", memory_check(a));
	printf("F vibe check %d \n", memory_check(f));
	printf("G vibe check %d \n", memory_check(g));
	printf("I vibe check %d \n", memory_check(i));

	memory_free(f);
	memory_free(i);
	memory_free(c);
	memory_free(d);
	memory_free(g);
	memory_free(h);

	printf("B A F G D C free\n");
	printf("B vibe check %d \n", memory_check(b));
	printf("A vibe check %d \n", memory_check(a));
	printf("F vibe check %d \n", memory_check(f));
	printf("G vibe check %d \n", memory_check(g));
	printf("D vibe check %d \n", memory_check(d));
	printf("C vibe check %d \n", memory_check(c));*/

	/*printf("FIRST HEAD %p\n", head_ptr);
	
	char *a = (char *)memory_alloc(23 * sizeof(char));
	char *b = (char *)memory_alloc(23 * sizeof(char));
	char *c = (char *)memory_alloc(10 * sizeof(char));
	char *d = (char *)memory_alloc(8 * sizeof(char));
	char *e = (char *)memory_alloc(24 * sizeof(char));

	char *f = (char *)memory_alloc(15 * sizeof(char));
	char *g = (char *)memory_alloc(24 * sizeof(char));
	char *h = (char *)memory_alloc(8 * sizeof(char));
	char *i = (char *)memory_alloc(18 * sizeof(char));
	char *j = (char *)memory_alloc(22 * sizeof(char));

	char *k = (char *)memory_alloc(23 * sizeof(char));
	char *l = (char *)memory_alloc(23 * sizeof(char));
	char *m = (char *)memory_alloc(15 * sizeof(char));
	char *n = (char *)memory_alloc(18 * sizeof(char));
	char *o = (char *)memory_alloc(24 * sizeof(char));

	char *p = (char *)memory_alloc(15 * sizeof(char));
	char *q = (char *)memory_alloc(21 * sizeof(char));
	char *r = (char *)memory_alloc(23 * sizeof(char));
	char *s = (char *)memory_alloc(18 * sizeof(char));
	char *t = (char *)memory_alloc(22 * sizeof(char));

	char *u = (char *)memory_alloc(23 * sizeof(char));
	char *v = (char *)memory_alloc(23 * sizeof(char));
	char *w = (char *)memory_alloc(10 * sizeof(char));

	memory_free(c);
	memory_free(b);
	memory_free(a);
	memory_free(t);
	memory_free(d);

	memory_free(r);
	memory_free(e);
	memory_free(s);
	memory_free(f);
	memory_free(h);

	memory_free(g);
	//memory_free(v);
	memory_free(p);
	memory_free(u);
	memory_free(q);
	
	memory_free(i);
	memory_free(k);
	memory_free(m);
	memory_free(l);
	memory_free(n);

	memory_free(j);
	//memory_free(w);
	memory_free(o);*/
	
	/*char* a = memory_alloc(23);
	memset(a, 'a', 23);
    char* b = memory_alloc(23);
	memset(b, 'b', 23);
    char* c = memory_alloc(10);
	memset(c, 'c', 10);
    char* d = memory_alloc(21);
	memset(d, 'd', 21);
	char* e = memory_alloc(19);
	memset(e, 'e', 19);
	char* f = memory_alloc(11);
	memset(f, 'f', 11);
	char* g = memory_alloc(13);
	memset(g, 'g', 13);
	char* h = memory_alloc(17);
	memset(h, 'h', 17);
	char* i = memory_alloc(13);
	memset(i, 'i', 13);
	char* j = memory_alloc(18);
	memset(j, 'j', 18);
	char* k = memory_alloc(12);
	memset(k, 'k', 12);
	char* l = memory_alloc(19);
	memset(l, 'l', 19);
	char* m = memory_alloc(23);
	memset(m, 'm', 23);
    
	memory_free(f);
    memory_free(c);
    memory_free(k);
    memory_free(d);
    memory_free(j);
    memory_free(l);
    memory_free(g);
    memory_free(a);
    memory_free(b);
    memory_free(m);

    char* n = memory_alloc(9);
	memset(n, 'n', 9);
    char* o = memory_alloc(21);
	memset(o, 'o', 21);
    char* p = memory_alloc(23);
	memset(p, 'p', 23);
    char* r = memory_alloc(18);
	memset(r, 'r', 18);
    char* s = memory_alloc(21);
	memset(s, 's', 21);
    char* t = memory_alloc(10);
	memset(t, 't', 10);
    char* u = memory_alloc(11);
	memset(u, 'u', 11);
    char* v = memory_alloc(13);
	memset(v, 'v', 13);
    char* x = memory_alloc(14);
	memset(x, 'x', 14);
    char* y = memory_alloc(22);
	memset(y, 'y', 22);
    char* z = memory_alloc(19);
	memset(z, 'z', 19);
    char* a1 = memory_alloc(21);
	memset(a1, 'A', 21);
    char* b1 = memory_alloc(18);
	memset(b1, 'B', 18);
    char* c1 = memory_alloc(17);
	memset(c1, 'C', 17);
    char* d1 = memory_alloc(8);
	memset(d1, 'D', 8);*/
	

	// Testovaci vypis pamate
	/*for (int i = 0; i < 100; i++)
		printf("\n%d %c %p", i, array[i], &array[i]);*/
	
	printf("\n%p %p %d\n", head_ptr, head_ptr->next, head_ptr->size);
	

	return 0;
}