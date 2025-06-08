package kr.ac.hansung.cse.hellospringdatajpa.controller;

import jakarta.validation.Valid;
import kr.ac.hansung.cse.hellospringdatajpa.entity.Product;
import kr.ac.hansung.cse.hellospringdatajpa.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@Controller
@RequestMapping("/products")
public class ProductController {

    @Autowired
    private ProductService service;

    @GetMapping({"", "/"}) // products 또는 /products/ 둘 다 매핑
    public String viewHomePage(Model model) {

        List<Product> listProducts = service.listAll();
        model.addAttribute("listProducts", listProducts);

        return "index";
    }

    @GetMapping("/new")
    @PreAuthorize("hasRole('ADMIN')")
    public String showNewProductPage(Model model) {

        Product product = new Product();
        model.addAttribute("product", product);

        return "new_product";
    }

    @GetMapping("/edit/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public String showEditProductPage(@PathVariable(name = "id") Long id, Model model) {

        Product product = service.get(id);
        model.addAttribute("product", product);

        return "edit_product";
    }

    // @ModelAttribute는  Form data (예: name=Laptop&brand=Samsung&madeIn=Korea&price=1000.00)를 Product 객체
    // @RequestBody는 HTTP 요청 본문에 포함된
    //  JSON 데이터(예: {"name": "Laptop", "brand": "Samsung", "madeIn": "Korea", "price": 1000.00})를 Product 객체에 매핑
    @PostMapping("/save")
    @PreAuthorize("hasRole('ADMIN')")
    public String saveProduct(@Valid @ModelAttribute("product") Product product, 
                            BindingResult bindingResult, 
                            Model model,
                            RedirectAttributes redirectAttributes) {
        if (bindingResult.hasErrors()) {
            redirectAttributes.addFlashAttribute("error", "상품 정보가 올바르지 않습니다.");
            return product.getId() == null ? "new_product" : "edit_product";
        }
        
        service.save(product);
        redirectAttributes.addFlashAttribute("success", 
            product.getId() == null ? "상품이 성공적으로 등록되었습니다." : "상품이 성공적으로 수정되었습니다.");
        return "redirect:/products";
    }

    @GetMapping("/delete/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public String deleteProduct(@PathVariable(name = "id") Long id, RedirectAttributes redirectAttributes) {

        service.delete(id);
        redirectAttributes.addFlashAttribute("success", "상품이 성공적으로 삭제되었습니다.");
        return "redirect:/products";
    }
}
