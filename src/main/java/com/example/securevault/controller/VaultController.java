package com.example.securevault.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import com.example.securevault.service.VaultService;

import jakarta.servlet.http.HttpSession;

@Controller
public class VaultController {

    @Autowired
    private VaultService vaultService;

    @PostMapping("/upload")
    public String uploadFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam("unlockTime") String unlockTime,
            HttpSession session) throws Exception {

        if (session.getAttribute("user") == null) {
            return "redirect:/login.html";
        }

        String fileId = vaultService.lockFile(file, unlockTime);
        return "redirect:/result.html?fileId=" + fileId;
    }

    @GetMapping("/download/{id}")
public ResponseEntity<?> downloadFile(
        @PathVariable String id,
        HttpSession session) throws Exception {

    if (session.getAttribute("user") == null) {
        return ResponseEntity.status(401).body("Unauthorized");
    }

    VaultService.VaultFile vf = vaultService.accessVault(id);
    if (vf == null) {
        return ResponseEntity.status(403).body("File locked");
    }

    return ResponseEntity.ok()
            .header("Content-Disposition",
                    "attachment; filename=\"" + vf.filename + "\"")
            .body(vf.data);
}

}
