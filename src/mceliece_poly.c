#include "mceliece_poly.h"

// 多项式创建
polynomial_t* polynomial_create(int max_degree) {
    polynomial_t *poly = malloc(sizeof(polynomial_t));
    if (!poly) return NULL;
    
    poly->coeffs = calloc(max_degree + 1, sizeof(gf_elem_t));
    if (!poly->coeffs) {
        free(poly);
        return NULL;
    }
    
    poly->degree = -1;  // 表示零多项式
    poly->max_degree = max_degree;
    return poly;
}

// 多项式释放
void polynomial_free(polynomial_t *poly) {
    if (poly) {
        if (poly->coeffs) free(poly->coeffs);
        free(poly);
    }
}

// Efficient polynomial evaluation using Horner's method
gf_elem_t polynomial_eval(const polynomial_t *poly, gf_elem_t x) {
    if (poly->degree < 0) {
        return 0; // Zero polynomial
    }

    // Use Horner's method: start with highest degree coefficient
    gf_elem_t result = poly->coeffs[poly->degree];

    // Iterate down to constant term
    for (int i = poly->degree - 1; i >= 0; i--) {
        result = gf_mul(result, x);
        result = gf_add(result, poly->coeffs[i]);
    }

    return result;
}

// 设置多项式系数并更新次数
void polynomial_set_coeff(polynomial_t *poly, int degree, gf_elem_t coeff) {
    if (degree > poly->max_degree) return;

    poly->coeffs[degree] = coeff;

    // 更新多项式次数
    if (coeff != 0 && degree > poly->degree) {
        poly->degree = degree;
    } else if (coeff == 0 && degree == poly->degree) {
        // 如果清零了最高次项，需要重新计算次数
        int new_degree = -1;
        for (int i = poly->max_degree; i >= 0; i--) {
            if (poly->coeffs[i] != 0) {
                new_degree = i;
                break;
            }
        }
        poly->degree = new_degree;
    }
}

void polynomial_copy(polynomial_t *dst, const polynomial_t *src) {
    if (!dst || !src) return;

    // 清零目标多项式
    memset(dst->coeffs, 0, (dst->max_degree + 1) * sizeof(gf_elem_t));

    // 确定要复制的项数，不能超过目标的最大容量
    int terms_to_copy = (src->degree < dst->max_degree) ? src->degree : dst->max_degree;

    // 如果源多项式是零多项式
    if (src->degree < 0) {
        dst->degree = -1;
        return;
    }

    // 复制系数
    for (int i = 0; i <= terms_to_copy; i++) {
        dst->coeffs[i] = src->coeffs[i];
    }

    // 设置次数
    dst->degree = terms_to_copy;

    // 如果发生了截断，需要重新检查最高次项是否为0
    while(dst->degree >= 0 && dst->coeffs[dst->degree] == 0) {
        dst->degree--;
    }
}

// 检查多项式是否为零
int polynomial_is_zero(const polynomial_t *poly) {
    return poly->degree < 0;
}

// 多项式加法（GF上就是异或）
void polynomial_add(polynomial_t *result, const polynomial_t *a, const polynomial_t *b) {
    int max_deg = (a->degree > b->degree) ? a->degree : b->degree;

    if (max_deg > result->max_degree) return;

    // 清零结果
    memset(result->coeffs, 0, (result->max_degree + 1) * sizeof(gf_elem_t));

    for (int i = 0; i <= max_deg; i++) {
        gf_elem_t coeff_a = (i <= a->degree) ? a->coeffs[i] : 0;
        gf_elem_t coeff_b = (i <= b->degree) ? b->coeffs[i] : 0;
        result->coeffs[i] = gf_add(coeff_a, coeff_b);
    }

    // 重新计算次数
    result->degree = -1;
    for (int i = max_deg; i >= 0; i--) {
        if (result->coeffs[i] != 0) {
            result->degree = i;
            break;
        }
    }
}



void polynomial_mul(polynomial_t *result, const polynomial_t *a, const polynomial_t *b) {
    int deg_res = a->degree + b->degree;
    assert(deg_res <= result->max_degree);

    // 清零结果
    memset(result->coeffs, 0, (result->max_degree + 1) * sizeof(gf_elem_t));
    result->degree = -1;

    for (int i = 0; i <= a->degree; i++) {
        for (int j = 0; j <= b->degree; j++) {
            gf_elem_t term = gf_mul(a->coeffs[i], b->coeffs[j]);
            result->coeffs[i + j] = gf_add(result->coeffs[i + j], term);
        }
    }

    // 更新次数
    for (int i = deg_res; i >= 0; i--) {
        if (result->coeffs[i] != 0) {
            result->degree = i;
            return;
        }
    }
}



void polynomial_div(polynomial_t *q, polynomial_t *r, const polynomial_t *a, const polynomial_t *b) {
    assert(b->degree >= 0); // 不能除以零多项式

    polynomial_copy(r, a); // 余数 r 初始化为 a

    if (q) {
        memset(q->coeffs, 0, (q->max_degree + 1) * sizeof(gf_elem_t));
        q->degree = -1;
    }

    // 如果被除数次数小于除数，商为0，余数为被除数本身
    if (r->degree < b->degree) {
        if (q) q->degree = -1;
        return;
    }

    int deg_b = b->degree;
    gf_elem_t lead_b_inv = gf_inv(b->coeffs[deg_b]);

    // 长除法核心循环
    for (int i = r->degree; i >= deg_b; i--) {
        gf_elem_t coeff = gf_mul(r->coeffs[i], lead_b_inv);

        if (coeff != 0) {
            if (q) {
                polynomial_set_coeff(q, i - deg_b, coeff);
            }
            // 从 r 中减去 (实际上是加上) coeff * x^(i-deg_b) * b
            for (int j = 0; j <= deg_b; j++) {
                gf_elem_t term = gf_mul(coeff, b->coeffs[j]);
                int r_idx = i - deg_b + j;
                if (r_idx <= r->max_degree) {
                    r->coeffs[r_idx] = gf_add(r->coeffs[r_idx], term);
                }
            }
        }
    }

    // 更新余数 r 的真实次数
    int new_r_degree = -1;
    for (int i = deg_b - 1; i >= 0; i--) {
        if (i <= r->max_degree && r->coeffs[i] != 0) {
            new_r_degree = i;
            break;
        }
    }
    r->degree = new_r_degree;
}

