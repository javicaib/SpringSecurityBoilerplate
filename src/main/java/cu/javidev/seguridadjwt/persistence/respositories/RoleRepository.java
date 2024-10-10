package cu.javidev.seguridadjwt.persistence.respositories;

import cu.javidev.seguridadjwt.persistence.entities.RoleEntity;
import cu.javidev.seguridadjwt.persistence.entities.RoleEnum;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<RoleEntity, Long> {
    Optional<RoleEntity> findByRoleEnum(RoleEnum roleEnum);
}