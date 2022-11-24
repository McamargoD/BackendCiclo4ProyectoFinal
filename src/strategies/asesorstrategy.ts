import {AuthenticationStrategy} from '@loopback/authentication';
import {service} from '@loopback/core';
import {HttpErrors} from '@loopback/rest';
import {UserProfile} from '@loopback/security';
import { profile } from 'console';
import {Request} from 'express';
import parseBearerToken from 'parse-bearer-token';
import {AutenticacionService} from '../services';


export class EstrategiaAsesor implements AuthenticationStrategy {
  name: string = 'asesor';

  constructor(
    @service(AutenticacionService)
    public servicioAutenticacion: AutenticacionService
  ){}

  async authenticate(request: Request): Promise<UserProfile | undefined> {
    let token = parseBearerToken(request)
    if(token) {
      let datos = this.servicioAutenticacion.validarTokenJWT(token);
      if(datos.asesor){
        let perfil: UserProfile = Object.assign({
          nombre:datos.data.nombre
        });
        return perfil;
      }else{
        new HttpErrors[401]('Token Falso')
      }
    }else{
      throw new HttpErrors[401]('No Incluyo Token')
    }
  }
}
