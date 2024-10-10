package cu.javidev.seguridadjwt.persistence.respositories;

import cu.javidev.seguridadjwt.persistence.entities.RoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<RoleEntity, Long> {
}