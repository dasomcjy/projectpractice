package com.project;

import java.security.Principal;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import com.project.entity.Member;
import com.project.service.MemberService;

import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class IndexController {
	
	private final MemberService memberService;
	
	
	@RequestMapping(value = "/")
	public String index() {
		
		
			return "index";
	}
	
	
	

	
		@RequestMapping(value = "/members/login")
		public String login() {
			return "login";
		}
		//회원가입 
//		@RequestMapping(value = "/join")
//		public String join() {
//			return "join";
//		}
		
//		//공지사항
//		@RequestMapping(value = "/notice")
//		public String notice() {
//			 
//			return "notice";
//		}
//		
//		//상품리스트
//		@RequestMapping(value = "/list")
//		public String list() {
//			 
//			return "list";
//		}
//		//상품상세
//			@RequestMapping(value = "/product")
//			public String product() {
//				 
//				return "product";
//			}
//			
//			
//		//카카오 로그인
//			@RequestMapping(value = "/kakao")
//			public String kakao() {
//				return "kakao";
//			}
//			
//			
//		//네이버 로그인	
//			@RequestMapping("/naver")
//		    public String naver() {
//		        return "naver";
//		    }
		

	}