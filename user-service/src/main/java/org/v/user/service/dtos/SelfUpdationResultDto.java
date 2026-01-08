package org.v.user.service.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SelfUpdationResultDto {
    private boolean isModified;
    private boolean shouldRemoveTokens;
    private Set<String> invalidInputs;
}
