#ifdef YOLODLL_EXPORTS
#define YOLODLL_API __declspec(dllexport)
#else
#define YOLODLL_API __declspec(dllexport)
#endif