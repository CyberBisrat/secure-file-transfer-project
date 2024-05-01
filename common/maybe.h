
#ifndef maybe_h
#define maybe_h
template <class T> class Maybe {
  public:
    T result;
    char const *error;
    bool is_error;

    Maybe<T>() {
        result = T();
        error = nullptr;
        is_error = false;
    }

    void set_error(char const *err) {
        error = err;
        is_error = true;
    }
    void set_result(T res) { result = res; }
};
#endif
