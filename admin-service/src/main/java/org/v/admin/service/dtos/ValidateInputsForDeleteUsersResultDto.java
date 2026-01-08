package org.v.admin.service.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.v.commons.models.UserModel;

import java.util.Map;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ValidateInputsForDeleteUsersResultDto {
    private Map<String, Object> mapOfErrors;
    private Set<UserModel> usersToDelete;
}
