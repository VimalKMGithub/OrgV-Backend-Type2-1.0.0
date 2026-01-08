package org.v.admin.service.controllers;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.v.admin.service.dtos.RoleCreationUpdationDto;
import org.v.admin.service.dtos.UserCreationDto;
import org.v.admin.service.dtos.UserUpdationDto;
import org.v.admin.service.services.AdminService;

import java.util.Map;
import java.util.Set;

import static org.v.commons.utils.ToggleUtility.DEFAULT_TOGGLE;

@RestController
@RequiredArgsConstructor
public class AdminController {
    private final AdminService adminService;

    @PostMapping("/create-users")
    public ResponseEntity<Map<String, Object>> createUsers(@RequestBody Set<UserCreationDto> dtos,
                                                           @RequestParam(defaultValue = DEFAULT_TOGGLE) String leniency,
                                                           HttpServletRequest request) throws Exception {
        return adminService.createUsers(dtos, leniency, request);
    }

    @DeleteMapping("/delete-users")
    public ResponseEntity<Map<String, Object>> deleteUsers(@RequestBody Set<String> usernamesOrEmailsOrIds,
                                                           @RequestParam(defaultValue = DEFAULT_TOGGLE) String hard,
                                                           @RequestParam(defaultValue = DEFAULT_TOGGLE) String leniency,
                                                           HttpServletRequest request) throws Exception {
        return adminService.deleteUsers(usernamesOrEmailsOrIds, hard, leniency, request);
    }

    @PostMapping("/read-users")
    public ResponseEntity<Map<String, Object>> readUsers(@RequestBody Set<String> usernamesOrEmailsOrIds,
                                                         @RequestParam(defaultValue = DEFAULT_TOGGLE) String leniency,
                                                         HttpServletRequest request) throws Exception {
        return adminService.readUsers(usernamesOrEmailsOrIds, leniency, request);
    }

    @PutMapping("/update-users")
    public ResponseEntity<Map<String, Object>> updateUsers(@RequestBody Set<UserUpdationDto> dtos,
                                                           @RequestParam(defaultValue = DEFAULT_TOGGLE) String leniency,
                                                           HttpServletRequest request) throws Exception {
        return adminService.updateUsers(dtos, leniency, request);
    }

    @PostMapping("/create-roles")
    public ResponseEntity<Map<String, Object>> createRoles(@RequestBody Set<RoleCreationUpdationDto> dtos,
                                                           @RequestParam(defaultValue = DEFAULT_TOGGLE) String leniency,
                                                           HttpServletRequest request) throws Exception {
        return adminService.createRoles(dtos, leniency, request);
    }

    @DeleteMapping("/delete-roles")
    public ResponseEntity<Map<String, Object>> deleteRoles(@RequestBody Set<String> roleNames,
                                                           @RequestParam(defaultValue = DEFAULT_TOGGLE) String force,
                                                           @RequestParam(defaultValue = DEFAULT_TOGGLE) String leniency,
                                                           HttpServletRequest request) {
        return adminService.deleteRoles(roleNames, force, leniency, request);
    }

    @PostMapping("/read-roles")
    public ResponseEntity<Map<String, Object>> readRoles(@RequestBody Set<String> roleNames,
                                                         @RequestParam(defaultValue = DEFAULT_TOGGLE) String leniency,
                                                         HttpServletRequest request) throws Exception {
        return adminService.readRoles(roleNames, leniency, request);
    }

    @PutMapping("/update-roles")
    public ResponseEntity<Map<String, Object>> updateRoles(@RequestBody Set<RoleCreationUpdationDto> dtos,
                                                           @RequestParam(defaultValue = DEFAULT_TOGGLE) String leniency,
                                                           HttpServletRequest request) throws Exception {
        return adminService.updateRoles(dtos, leniency, request);
    }

    @PostMapping("/read-permissions")
    public ResponseEntity<Map<String, Object>> readPermissions(@RequestBody Set<String> permissionNames,
                                                               @RequestParam(defaultValue = DEFAULT_TOGGLE) String leniency,
                                                               HttpServletRequest request) throws Exception {
        return adminService.readPermissions(permissionNames, leniency, request);
    }
}
