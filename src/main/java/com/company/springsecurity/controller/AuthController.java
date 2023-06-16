package com.company.springsecurity.controller;



import com.company.springsecurity.SecurityService.UserDetailsImpl;
import com.company.springsecurity.model.ERole;
import com.company.springsecurity.model.Role;
import com.company.springsecurity.model.User;
import com.company.springsecurity.model.VerificationToken;
import com.company.springsecurity.payload.request.LoginRequest;
import com.company.springsecurity.payload.request.SignupRequest;
import com.company.springsecurity.payload.response.JwtResponse;
import com.company.springsecurity.payload.response.MessageResponse;
import com.company.springsecurity.repository.RoleRepository;
import com.company.springsecurity.repository.UserRepository;
import com.company.springsecurity.repository.VerificationTokenRepository;
import com.company.springsecurity.security.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;


import java.util.*;

import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    private VerificationTokenRepository tokenRepository;

    @Autowired
    private JavaMailSender mailSender;
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

//    @PostMapping("/signup")
//    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
//
//        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
//            return ResponseEntity
//                    .badRequest()
//                    .body(new MessageResponse("Error: Email is already in use!"));
//        }
//
//        // Create new user's account
//        User user = new User(signUpRequest.getName(),
//                signUpRequest.getSurname(),
//                signUpRequest.getEmail(),
//                encoder.encode(signUpRequest.getPassword()));
//
//        String strRole = "user";
//
//        Set<Role> roles = new HashSet<>();
//        if(strRole.equals("admin")){
//            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
//                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//            roles.add(adminRole);
//        }
//        else if(strRole.equals("admin")){
//            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
//                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//            roles.add(adminRole);
//        }
//        if(strRole.equals("mod")){
//            Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
//                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//                           roles.add(modRole);
//        }
//        else{
//            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
//                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//                        roles.add(userRole);
//        }
//
//        user.setRoles(roles);
//        userRepository.save(user);
//
//        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
//    }


    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getName(),
                signUpRequest.getSurname(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));
        user.setActive(false);

        // save user to database
        userRepository.save(user);

        // create verification token for the user and save it to database
        VerificationToken token = new VerificationToken();
        token.setToken(UUID.randomUUID().toString());
        token.setUser(user);
        token.setExpiryDate(60);  // token expires after 60 minutes
        tokenRepository.save(token);

        // send the email
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(user.getEmail());
        message.setSubject("Complete Registration!");
        message.setText("To confirm your account, please click here : "
                +"http://localhost:8080/api/auth/registrationConfirm?token="+token.getToken());
        mailSender.send(message);

        return ResponseEntity.ok(new MessageResponse("User registered successfully! Check your email to verify your account."));
    }

    @GetMapping("/registrationConfirm")
    public ResponseEntity<?> confirmRegistration(@RequestParam("token") String token) {
        VerificationToken verificationToken = tokenRepository.findByToken(token);

        if (verificationToken == null) {
            return ResponseEntity.badRequest().body(new MessageResponse("Invalid verification token!"));
        }

        // check if the token is expired
        if (verificationToken.getExpiryDate().before(new Date())) {
            return ResponseEntity.badRequest().body(new MessageResponse("The verification token is expired!"));
        }

        User user = verificationToken.getUser();
        user.setActive(true);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User activated successfully!"));
    }


}
